// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"storj.io/common/cfgstruct"
	"storj.io/common/errs2"
	"storj.io/common/fpath"
	"storj.io/common/process"
	mcpserver "storj.io/edge/pkg/mcp-server"
)

var (
	rootCmd = &cobra.Command{
		Use:   "mcp-server",
		Short: "Storj MCP (Model Context Protocol) Server",
		Args:  cobra.OnlyValidArgs,
	}
	runCmd = &cobra.Command{
		Use:   "run",
		Short: "Run the service",
		Args:  cobra.ExactArgs(0),
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

	runCfg   mcpserver.Config
	setupCfg mcpserver.Config

	confDir string
)

func init() {
	defaultConfDir := fpath.ApplicationDir("storj", "mcp-server")
	cfgstruct.SetupFlag(zap.L(), rootCmd, &confDir, "config-dir", defaultConfDir, "main directory for mcp-server configuration")
	defaults := cfgstruct.DefaultsFlag(rootCmd)

	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(setupCmd)

	process.Bind(runCmd, &runCfg, defaults, cfgstruct.ConfDir(confDir))
	process.Bind(setupCmd, &setupCfg, defaults, cfgstruct.ConfDir(confDir), cfgstruct.SetupMode())

	cfgstruct.SetBoolAnnotation(rootCmd.PersistentFlags(), "config-dir", cfgstruct.BasicHelpAnnotationName, true)
}

func cmdRun(cmd *cobra.Command, _ []string) (err error) {
	ctx, cancel := process.Ctx(cmd)
	defer cancel()

	log := zap.L()

	if err := process.InitMetricsWithHostname(ctx, log, nil); err != nil {
		return errs.New("Failed to initialize telemetry batcher: %w", err)
	}

	log.Info("Starting Storj MCP (Model Context Protocol) Server")

	if err := runCfg.Auth.Validate(); err != nil {
		return err
	}
	peer, err := mcpserver.New(log, runCfg)
	if err != nil {
		return err
	}

	// if peer.Run() fails, we want to ensure the context is canceled so we
	// don't hang on ctx.Done before closing the peer.
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		<-ctx.Done()
		return errs2.IgnoreCanceled(peer.Close())
	})

	g.Go(func() error {
		return errs2.IgnoreCanceled(peer.Run(ctx))
	})

	return g.Wait()
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
