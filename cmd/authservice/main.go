// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"context"
	"net/http"

	"github.com/spf13/cobra"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/fpath"
	"storj.io/common/storj"
	"storj.io/private/cfgstruct"
	"storj.io/private/process"
	"storj.io/stargate/auth"
	"storj.io/stargate/auth/httpauth"
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
		Short: "Run migrations for the auth service",
		RunE:  cmdMigrationRun,
	}

	config  Config
	confDir string
)

// Config is the config.
type Config struct {
	Endpoint          string   `help:"endpoint to return to clients" default:""`
	AuthToken         string   `help:"auth token to validate requests" default:""`
	AllowedSatellites []string `help:"List of satellite addresses allowed for incoming access grants"`

	KVBackend string `help:"key/value store backend url" default:"memory://"`

	ListenAddr    string `user:"true" help:"public address to listen on" default:":8000"`
	ListenAddrTLS string `user:"true" help:"public tls address to listen on" default:":8443"`

	LetsEncrypt bool   `user:"true" help:"use lets-encrypt to handle TLS certificates" default:"false"`
	CertFile    string `user:"true" help:"server certificate file" devDefault:"" releaseDefault:"server.crt.pem"`
	KeyFile     string `user:"true" help:"server key file" devDefault:"" releaseDefault:"server.key.pem"`
	PublicURL   string `user:"true" help:"public url for the server" devDefault:"http://localhost:8080" releaseDefault:""`
}

func init() {
	defaultConfDir := fpath.ApplicationDir("storj", "authservice")
	cfgstruct.SetupFlag(zap.L(), rootCmd, &confDir, "config-dir", defaultConfDir, "main directory for configuration")
	defaults := cfgstruct.DefaultsFlag(rootCmd)

	rootCmd.AddCommand(runCmd)
	runCmd.AddCommand(runMigrationCmd)
	process.Bind(runCmd, &config, defaults, cfgstruct.ConfDir(confDir))
	process.Bind(runMigrationCmd, &config, defaults, cfgstruct.ConfDir(confDir))
}

func main() {
	process.Exec(rootCmd)
}

func cmdRun(cmd *cobra.Command, args []string) (err error) {
	log := zap.L()

	// Confirm that all satellites in config.AllowedSatellites is a valid storj
	// node URL.
	for _, sat := range config.AllowedSatellites {
		_, err := storj.ParseNodeURL(sat)
		if err != nil {
			return err
		}
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
	res := httpauth.New(log.Named("resources"), db, config.Endpoint, config.AuthToken)

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
