// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"net/http"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"storj.io/common/fpath"
	"storj.io/common/storj"
	"storj.io/private/cfgstruct"
	"storj.io/private/process"
	"storj.io/stargate/auth"
	"storj.io/stargate/auth/httpauth"
	"storj.io/stargate/auth/memauth"
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

	config  Config
	confDir string
)

// Config is the config.
type Config struct {
	Endpoint          string   `help:"endpoint to return to clients" default:""`
	AuthToken         string   `help:"auth token to validate requests" default:""`
	ListenAddr        string   `help:"address to listen for incoming connections" releaseDefault:"" devDefault:"localhost:8000"`
	AllowedSatellites []string `help:"List of satellite addresses allowed for incoming access grants"`
}

func init() {
	defaultConfDir := fpath.ApplicationDir("storj", "authservice")
	cfgstruct.SetupFlag(zap.L(), rootCmd, &confDir, "config-dir", defaultConfDir, "main directory for configuration")
	defaults := cfgstruct.DefaultsFlag(rootCmd)

	rootCmd.AddCommand(runCmd)
	process.Bind(runCmd, &config, defaults, cfgstruct.ConfDir(confDir))
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

	kv := memauth.New()
	db := auth.NewDatabase(kv, config.AllowedSatellites)

	res := httpauth.New(db, config.Endpoint, config.AuthToken)

	log.Info("listening for incoming connections", zap.String("address", config.ListenAddr))
	return http.ListenAndServe(config.ListenAddr, res)
}
