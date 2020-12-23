// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/spf13/cobra"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/fpath"
	"storj.io/common/storj"
	"storj.io/gateway-mt/auth"
	"storj.io/gateway-mt/auth/httpauth"
	"storj.io/private/cfgstruct"
	"storj.io/private/process"
)

var (
	rootCmd = &cobra.Command{
		Use:   "authservice",
		Short: "The hosted gateway auth service",
		Args:  cobra.OnlyValidArgs,
	}
	runCmd = &cobra.Command{
		Use:   "run",
		Short: "Run the auth service",
		RunE:  cmdRun,
	}
	runMigrationCmd = &cobra.Command{
		Use:   "migration",
		Short: "Create or update the database schema, then quit",
		RunE:  cmdMigrationRun,
	}
	runHealthCheckCmd = &cobra.Command{
		Use:   "health-check [URL]",
		Short: "Check the health endpoint",
		RunE:  cmdHealthCheckRun,
	}

	config  Config
	confDir string
)

// Config is the config.
type Config struct {
	Endpoint          string   `help:"Gateway endpoint URL to return to clients" default:""`
	AuthToken         string   `help:"auth security token to validate requests" releaseDefault:"" devDefault:""`
	AllowedSatellites []string `help:"list of satellite addresses allowed for incoming access grants"`

	KVBackend string `help:"key/value store backend url" default:"memory://"`
	Migration bool   `help:"create or update the database schema, and then continue service startup" default:"false"`

	ListenAddr    string `user:"true" help:"public address to listen on" default:":8000"`
	ListenAddrTLS string `user:"true" help:"public tls address to listen on" default:":8443"`

	LetsEncrypt bool   `user:"true" help:"use lets-encrypt to handle TLS certificates" default:"false"`
	CertFile    string `user:"true" help:"server certificate file" devDefault:"" releaseDefault:"server.crt.pem"`
	KeyFile     string `user:"true" help:"server key file" devDefault:"" releaseDefault:"server.key.pem"`
	PublicURL   string `user:"true" help:"public url for the server, for the TLS certificate" devDefault:"http://localhost:8080" releaseDefault:""`
}

func init() {
	defaultConfDir := fpath.ApplicationDir("storj", "authservice")
	cfgstruct.SetupFlag(zap.L(), rootCmd, &confDir, "config-dir", defaultConfDir, "main directory for configuration")
	defaults := cfgstruct.DefaultsFlag(rootCmd)

	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(runHealthCheckCmd)

	runCmd.AddCommand(runMigrationCmd)

	process.Bind(runCmd, &config, defaults, cfgstruct.ConfDir(confDir))
	process.Bind(runMigrationCmd, &config, defaults, cfgstruct.ConfDir(confDir))
	process.Bind(runHealthCheckCmd, &config, defaults, cfgstruct.ConfDir(confDir))
}

func main() {
	process.Exec(rootCmd)
}

func cmdRun(cmd *cobra.Command, args []string) (err error) {
	if config.Migration {
		if err = cmdMigrationRun(cmd, args); err != nil {
			return err
		}
	}

	log := zap.L()

	// Confirm that all satellites in config.AllowedSatellites is a valid storj
	// node URL.
	for _, sat := range config.AllowedSatellites {
		_, err := storj.ParseNodeURL(sat)
		if err != nil {
			return err
		}
	}

	if len(config.AllowedSatellites) == 0 {
		return errs.New("allowed satellites parameter '--allowed-satellites' is required")
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

	kv, err := openKV(config.KVBackend)
	if err != nil {
		return errs.Wrap(err)
	}

	allowedSats, err := auth.RemoveNodeIDs(config.AllowedSatellites)
	if err != nil {
		return errs.Wrap(err)
	}
	db := auth.NewDatabase(kv, allowedSats)
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

	errors := make(chan error, 2)
	launch := func(fn func() error) {
		go func() {
			err := fn()
			if err != nil {
				errors <- err
			}
		}()
	}

	launch(func() error {
		if tlsConfig == nil {
			return nil
		}

		log.Info("listening for incoming TLS connections", zap.String("address", config.ListenAddrTLS))

		return (&http.Server{
			Handler:   handler,
			TLSConfig: tlsConfig,
			Addr:      config.ListenAddrTLS,
		}).ListenAndServeTLS("", "")
	})

	launch(func() error {
		log.Info("listening for incoming connections", zap.String("address", config.ListenAddr))

		return (&http.Server{
			Handler: handler,
			Addr:    config.ListenAddr,
		}).ListenAndServe()
	})

	res.SetStartupDone()

	// return at the first error
	return <-errors
}

func cmdMigrationRun(cmd *cobra.Command, args []string) (err error) {
	ctx, _ := process.Ctx(cmd)

	kv, err := openKV(config.KVBackend)
	if err != nil {
		return errs.Wrap(err)
	}

	migrator, ok := kv.(interface {
		MigrateToLatest(ctx context.Context) error
	})
	if !ok {
		return errs.New("database backend does not support migrations")
	}

	if err := migrator.MigrateToLatest(ctx); err != nil {
		return errs.Wrap(err)
	}

	return nil
}

func cmdHealthCheckRun(cmd *cobra.Command, args []string) (err error) {
	ctx, _ := process.Ctx(cmd)

	url := "http://localhost:8000/v1/health/live"
	if len(args) > 0 {
		url = args[0]
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	client := http.Client{
		Timeout: 30 * time.Second,
	}

	res, err := client.Do(req)
	if err != nil {
		return err
	}
	err = res.Body.Close()
	if err != nil {
		return err
	}

	if res.StatusCode != 200 {
		return errs.New("health check not ok %d", res.StatusCode)
	}

	return nil
}
