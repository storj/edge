// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"net"
	"os"
	"path/filepath"

	"github.com/minio/cli"
	"github.com/spf13/cobra"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/cfgstruct"
	"storj.io/common/fpath"
	"storj.io/common/process"
	"storj.io/edge/pkg/simplegateway"
	minio "storj.io/minio/cmd"
)

// Config is the config for running the gateway.
type Config struct {
	Server simplegateway.Config
	Minio  simplegateway.MinioConfig
}

// TODO: A lot of this is mostly a copy of gateway-st (storj.io/gateway)
// We should try to re-use code instead of duplicating it here.
var (
	// ConfigError is a class of errors relating to config validation.
	ConfigError = errs.Class("gateway configuration")

	// rootCmd represents the base gateway command when called without any subcommands.
	rootCmd = &cobra.Command{
		Use:   "simplegateway",
		Short: "Simple file-based S3 gateway supporting only Get and Put object operations",
		Args:  cobra.OnlyValidArgs,
	}
	runCmd = &cobra.Command{
		Use:   "run",
		Short: "Run the S3 gateway",
		RunE:  cmdRun,
	}
	setupCmd = &cobra.Command{
		Use:         "setup",
		Short:       "Create configuration file",
		Args:        cobra.ExactArgs(0),
		Annotations: map[string]string{"type": "setup"},
		RunE:        cmdSetup,
		Hidden:      true,
	}

	runCfg   Config
	setupCfg Config

	confDir string
)

func init() {
	defaultConfDir := fpath.ApplicationDir("storj", "simplegateway")
	cfgstruct.SetupFlag(zap.L(), rootCmd, &confDir, "config-dir", defaultConfDir, "main directory for gateway configuration")
	defaults := cfgstruct.DefaultsFlag(rootCmd)

	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(setupCmd)

	process.Bind(runCmd, &runCfg, defaults, cfgstruct.ConfDir(confDir))
	process.Bind(setupCmd, &setupCfg, defaults, cfgstruct.ConfDir(confDir), cfgstruct.SetupMode())
}

func cmdRun(cmd *cobra.Command, args []string) (err error) {
	ctx, cancel := process.Ctx(cmd)
	defer cancel()

	if err := validateConfig(runCfg); err != nil {
		return ConfigError.Wrap(err)
	}

	address := runCfg.Server.Address
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if host == "" {
		address = net.JoinHostPort("127.0.0.1", port)
	}

	log := zap.L()

	if err := process.InitMetricsWithHostname(ctx, log, nil); err != nil {
		return errs.New("Failed to initialize telemetry batcher: %w", err)
	}

	zap.S().Info("Starting S3 Gateway")
	zap.S().Infof("Endpoint: %s", address)
	zap.S().Infof("Access key: %s", runCfg.Minio.AccessKey)
	zap.S().Infof("Secret key: %s", runCfg.Minio.SecretKey)

	err = minio.RegisterGatewayCommand(cli.Command{
		Name:  "storj",
		Usage: "Storj",
		Action: func(cliCtx *cli.Context) error {
			minio.StartGateway(cliCtx, simplegateway.New(runCfg.Server.DataDir))
			return errs.New("unexpected minio exit")
		},
		HideHelpCommand: true,
	})
	if err != nil {
		return err
	}

	err = os.Setenv("MINIO_ACCESS_KEY", runCfg.Minio.AccessKey)
	if err != nil {
		return err
	}
	err = os.Setenv("MINIO_SECRET_KEY", runCfg.Minio.SecretKey)
	if err != nil {
		return err
	}

	minio.Main([]string{"storj", "gateway", "storj",
		"--address", runCfg.Server.Address, "--config-dir", runCfg.Minio.ConfigDir, "--quiet",
		"--compat"})
	return errs.New("unexpected minio exit")
}

func cmdSetup(cmd *cobra.Command, _ []string) error {
	setupDir, err := filepath.Abs(confDir)
	if err != nil {
		return err
	}

	valid, _ := fpath.IsValidSetupDir(setupDir)
	if !valid {
		return errs.New("configuration already exists (%v)", setupDir)
	}

	if err = os.MkdirAll(setupDir, 0700); err != nil {
		return err
	}

	return process.SaveConfig(cmd, filepath.Join(setupDir, "config.yaml"))
}

func main() {
	process.Exec(rootCmd)
}

func validateConfig(config Config) error {
	if config.Server.DataDir == "" {
		return errs.New("server.data-dir is required")
	}
	if config.Minio.AccessKey == "" {
		return errs.New("minio.access-key is required")
	}
	if config.Minio.SecretKey == "" {
		return errs.New("minio.access-key is required")
	}
	return nil
}
