// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"storj.io/common/errs2"
	"storj.io/common/fpath"
	"storj.io/gateway-mt/internal/register"
	"storj.io/gateway-mt/pkg/auth"
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
	registerCmd = &cobra.Command{
		Use:    "register",
		Short:  "Register credentials @ authservice via HTTP or DRPC",
		Args:   cobra.ExactArgs(1),
		RunE:   cmdRegister,
		Hidden: true,
	}

	config  auth.Config
	confDir string

	registerConfig struct {
		Address   string `help:"authservice to register access to" dev:"drpc://localhost:20002" release:"drpcs://auth.us1.storjshare.io:7777"`
		Public    bool   `help:"whether access grant can be retrieved from authservice by providing only Access Key ID without Secret Access Key" default:"false"`
		FormatEnv bool   `help:"environmental-variable format of credentials; for using in scripts" default:"false"`
	}
)

func init() {
	defaultConfDir := fpath.ApplicationDir("storj", "authservice")
	cfgstruct.SetupFlag(zap.L(), rootCmd, &confDir, "config-dir", defaultConfDir, "main directory for configuration")
	defaults := cfgstruct.DefaultsFlag(rootCmd)

	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(registerCmd)

	runCmd.AddCommand(runMigrationCmd)

	process.Bind(runCmd, &config, defaults, cfgstruct.ConfDir(confDir))
	process.Bind(runMigrationCmd, &config, defaults, cfgstruct.ConfDir(confDir))
	process.Bind(registerCmd, &registerConfig, defaults)
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

func cmdRegister(cmd *cobra.Command, args []string) (err error) {
	ctx, _ := process.Ctx(cmd)

	res, err := register.Access(ctx, registerConfig.Address, args[0], registerConfig.Public)
	if err != nil {
		return err
	}

	if registerConfig.FormatEnv {
		fmt.Printf("AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\nAWS_ENDPOINT=%s\n",
			res.AccessKeyID, res.SecretKey, res.Endpoint)
	} else {
		fmt.Println(res)
	}

	return nil
}
