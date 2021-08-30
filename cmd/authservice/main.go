// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"context"
	"net/http"
	"time"

	"github.com/spf13/cobra"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/fpath"
	"storj.io/gateway-mt/auth"
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

	config  auth.Config
	confDir string
)

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
	ctx, _ := process.Ctx(cmd)

	if config.Migration {
		if err = cmdMigrationRun(cmd, args); err != nil {
			return err
		}
	}

	log := zap.L()

	if err := process.InitMetricsWithHostname(ctx, log, nil); err != nil {
		zap.S().Warn("Failed to initialize telemetry batcher: ", err)
	}

	return auth.Run(ctx, config, confDir, log)
}

func cmdMigrationRun(cmd *cobra.Command, args []string) (err error) {
	ctx, _ := process.Ctx(cmd)

	kv, err := auth.OpenKV(ctx, zap.L().Named("migration"), config.KVBackend)
	if err != nil {
		return errs.Wrap(err)
	}
	defer func() { err = errs.Combine(err, kv.Close()) }()

	migrator, ok := kv.(interface {
		MigrateToLatest(ctx context.Context) error
	})
	if !ok {
		return errs.New("database backend %T does not support migrations", kv)
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
