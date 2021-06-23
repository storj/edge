// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package auth

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/sync2"
	"storj.io/gateway-mt/auth/authdb"
	"storj.io/gateway-mt/auth/httpauth"
	"storj.io/gateway-mt/auth/satellitelist"
	"storj.io/gateway-mt/pkg/server"
)

// Config is the config.
type Config struct {
	Endpoint          string        `help:"Gateway endpoint URL to return to clients" default:""`
	AuthToken         string        `help:"auth security token to validate requests" releaseDefault:"" devDefault:""`
	AllowedSatellites []string      `help:"list of satellite NodeURLs allowed for incoming access grants" default:"https://www.storj.io/dcs-satellites"`
	CacheExpiration   time.Duration `help:"length of time satellite addresses are cached for" default:"10m"`

	KVBackend string `help:"key/value store backend url" default:""`
	Migration bool   `help:"create or update the database schema, and then continue service startup" default:"false"`

	ListenAddr    string `user:"true" help:"public HTTP address to listen on" default:":8000"`
	ListenAddrTLS string `user:"true" help:"public HTTPS address to listen on" default:":8443"`

	LetsEncrypt bool   `user:"true" help:"use lets-encrypt to handle TLS certificates" default:"false"`
	CertFile    string `user:"true" help:"server certificate file" default:""`
	KeyFile     string `user:"true" help:"server key file" default:""`
	PublicURL   string `user:"true" help:"public url for the server, for the TLS certificate" devDefault:"http://localhost:8080" releaseDefault:""`

	DeleteUnused DeleteUnusedConfig
}

// DeleteUnusedConfig is a config struct for configuring unused records deletion
// chores.
type DeleteUnusedConfig struct {
	Run                bool          `help:"whether to run unused records deletion chore" default:"false"`
	Interval           time.Duration `help:"interval unused records deletion chore waits to start next iteration" default:"24h"`
	AsOfSystemInterval time.Duration `help:"the interval specified in AS OF SYSTEM in unused records deletion chore query as negative interval" default:"5s"`
	SelectSize         int           `help:"batch size of records selected for deletion at a time" default:"10000"`
	DeleteSize         int           `help:"batch size of records to delete from selected records at a time" default:"1000"`
}

// Run is the entry point function
// exposed function to enable its usage in testsuites.
func Run(ctx context.Context, config Config, confDir string, log *zap.Logger) error {
	if len(config.AllowedSatellites) == 0 {
		return errs.New("allowed satellites parameter '--allowed-satellites' is required")
	}
	allowedSats, areSatsDynamic, err := satellitelist.LoadSatelliteIDs(ctx, config.AllowedSatellites)
	if err != nil {
		return errs.Wrap(err)
	}
	if len(allowedSats) == 0 {
		return errs.New("allowed satellites parameter '--allowed-satellites' resolved to zero satellites")
	}

	if config.Endpoint == "" {
		return errs.New("endpoint parameter '--endpoint' is required")
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil {
		return errs.Wrap(err)
	}
	if endpoint.Scheme != "http" && endpoint.Scheme != "https" {
		return errs.New("unexpected scheme found in endpoint parameter %s", endpoint.Scheme)
	}

	kv, err := OpenKV(ctx, log.Named("db"), config.KVBackend)
	if err != nil {
		return errs.Wrap(err)
	}
	defer func() { err = errs.Combine(err, kv.Close()) }()

	db := authdb.NewDatabase(kv, allowedSats)
	res := httpauth.New(log.Named("resources"), db, endpoint, config.AuthToken)

	tlsInfo := &TLSInfo{
		LetsEncrypt: config.LetsEncrypt,
		CertFile:    config.CertFile,
		KeyFile:     config.KeyFile,
		PublicURL:   config.PublicURL,
		ConfigDir:   confDir,
	}

	tlsConfig, handler, err := configureTLS(tlsInfo, res)
	if err != nil {
		return err
	}

	// logging. do not log paths - paths have access keys in them.
	handler = server.LogResponsesNoPaths(log, server.LogRequestsNoPaths(log, handler))

	errors := make(chan error, 2)
	launch := func(fn func() error) {
		go func() {
			err := fn()
			if err != nil {
				errors <- err
			}
		}()
	}

	if areSatsDynamic {
		launch(func() error {
			return sync2.NewCycle(config.CacheExpiration).Run(ctx, func(ctx context.Context) error {
				log.Debug("Reloading allowed satellite list")
				allowedSatelliteIDs, _, err := satellitelist.LoadSatelliteIDs(ctx, config.AllowedSatellites)
				if err != nil {
					log.Warn("Error reloading allowed satellite list", zap.Error(err))
				} else {
					db.SetAllowedSatellites(allowedSatelliteIDs)
				}
				return nil
			})
		})
	}

	launch(func() error {
		log.Info("listening for incoming HTTP connections", zap.String("address", config.ListenAddr))

		return (&http.Server{
			Handler: handler,
			Addr:    config.ListenAddr,
		}).ListenAndServe()
	})

	listener, err := net.Listen("tcp", config.ListenAddrTLS)
	if err != nil {
		return err
	}
	err = listenAndServe(ctx, log, listener, tlsConfig, handler)
	if err != nil {
		return err
	}

	res.SetStartupDone()

	// return at the first error
	return <-errors
}
