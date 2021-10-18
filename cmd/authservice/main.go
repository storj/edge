// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"context"

	"github.com/spf13/cobra"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"storj.io/common/errs2"
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

	config  auth.Config
	confDir string
)

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

	p, err := auth.New(ctx, log, config, confDir)
	if err != nil {
		return err
	}

	var g errgroup.Group

	g.Go(func() error {
		<-ctx.Done()
		return errs2.IgnoreCanceled(p.Close())
	})

	g.Go(func() error {
		return errs2.IgnoreCanceled(p.Run(ctx))
	})

	return g.Wait()
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
