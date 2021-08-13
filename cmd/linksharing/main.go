// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/fpath"
	"storj.io/common/lrucache"
	"storj.io/gateway-mt/pkg/linksharing"
	"storj.io/gateway-mt/pkg/linksharing/httpserver"
	"storj.io/gateway-mt/pkg/linksharing/sharing"
	"storj.io/private/cfgstruct"
	"storj.io/private/process"
)

// LinkSharing defines link sharing configuration.
type LinkSharing struct {
	Address               string        `user:"true" help:"public address to listen on" default:":8080"`
	AddressTLS            string        `user:"true" help:"public tls address to listen on" default:":8443"`
	LetsEncrypt           bool          `user:"true" help:"use lets-encrypt to handle TLS certificates" default:"false"`
	CertFile              string        `user:"true" help:"server certificate file" devDefault:"" releaseDefault:"server.crt.pem"`
	KeyFile               string        `user:"true" help:"server key file" devDefault:"" releaseDefault:"server.key.pem"`
	PublicURL             string        `user:"true" help:"comma separated list of public urls for the server" devDefault:"http://localhost:8080" releaseDefault:""`
	GeoLocationDB         string        `user:"true" help:"maxmind database file path" devDefault:"" releaseDefault:""`
	TxtRecordTTL          time.Duration `user:"true" help:"max ttl (seconds) for website hosting txt record cache" devDefault:"10s" releaseDefault:"1h"`
	AuthService           authServiceConfig
	DNSServer             string   `user:"true" help:"dns server address to use for TXT resolution" default:"1.1.1.1:53"`
	StaticSourcesPath     string   `user:"true" help:"the path to where web assets are located" default:"./pkg/linksharing/web/static"`
	Templates             string   `user:"true" help:"the path to where renderable templates are located" default:"./pkg/linksharing/web"`
	LandingRedirectTarget string   `user:"true" help:"the url to redirect empty requests to" default:"https://www.storj.io/"`
	RedirectHTTPS         bool     `user:"true" help:"redirect to HTTPS" devDefault:"false" releaseDefault:"true"`
	UseQosAndCC           bool     `user:"true" help:"use congestion control and QOS settings" default:"true"`
	ClientTrustedIPSList  []string `user:"true" help:"list of clients IPs (comma separated) which are trusted; usually used when the service run behinds gateways, load balancers, etc."`
	UseClientIPHeaders    bool     `user:"true" help:"use the headers sent by the client to identify its IP. When true the list of IPs set by --client-trusted-ips-list, when not empty, is used" default:"true"`
	ConnectionPool        connectionPoolConfig
}

type authServiceConfig struct {
	BaseURL string `user:"true" help:"base url to use for resolving access key ids" default:""`
	Token   string `user:"true" help:"auth token for giving access to the auth service" default:""`
	Cache   authServiceCacheConfig
}

type authServiceCacheConfig struct {
	Expiration time.Duration `user:"true" help:"how long to keep cached access grants in cache" default:"24h"`
	Capacity   int           `user:"true" help:"how many cached access grants to keep in cache" default:"1000"`
}

// connectionPoolConfig is a config struct for configuring RPC connection pool options.
type connectionPoolConfig struct {
	Capacity       int           `user:"true" help:"RPC connection pool capacity" default:"100"`
	KeyCapacity    int           `user:"true" help:"RPC connection pool key capacity" default:"5"`
	IdleExpiration time.Duration `user:"true" help:"RPC connection pool idle expiration" default:"2m0s"`
}

var (
	rootCmd = &cobra.Command{
		Use:   "link sharing service",
		Short: "Link Sharing Service",
	}
	runCmd = &cobra.Command{
		Use:   "run",
		Short: "Run the link sharing service",
		RunE:  cmdRun,
	}
	setupCmd = &cobra.Command{
		Use:         "setup",
		Short:       "Create config files",
		RunE:        cmdSetup,
		Annotations: map[string]string{"type": "setup"},
	}

	runCfg   LinkSharing
	setupCfg LinkSharing

	confDir string
)

func init() {
	defaultConfDir := fpath.ApplicationDir("storj", "linksharing")
	cfgstruct.SetupFlag(zap.L(), rootCmd, &confDir, "config-dir", defaultConfDir, "main directory for link sharing configuration")
	defaults := cfgstruct.DefaultsFlag(rootCmd)
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(setupCmd)
	process.Bind(runCmd, &runCfg, defaults, cfgstruct.ConfDir(confDir))
	process.Bind(setupCmd, &setupCfg, defaults, cfgstruct.ConfDir(confDir), cfgstruct.SetupMode())
}

func cmdRun(cmd *cobra.Command, args []string) (err error) {
	ctx, _ := process.Ctx(cmd)
	log := zap.L()

	if err := process.InitMetricsWithHostname(ctx, log, nil); err != nil {
		zap.S().Warn("Failed to initialize telemetry batcher: ", err)
	}

	publicURLs := strings.Split(runCfg.PublicURL, ",")

	peer, err := linksharing.New(log, linksharing.Config{
		Server: httpserver.Config{
			Name:       "Link Sharing",
			Address:    runCfg.Address,
			AddressTLS: runCfg.AddressTLS,
			TLSConfig: &httpserver.TLSConfig{
				LetsEncrypt: runCfg.LetsEncrypt,
				CertFile:    runCfg.CertFile,
				KeyFile:     runCfg.KeyFile,
				PublicURLs:  publicURLs,
				ConfigDir:   confDir,
			},
			ShutdownTimeout: -1,
		},
		Handler: sharing.Config{
			URLBases:              publicURLs,
			Templates:             runCfg.Templates,
			StaticSourcesPath:     runCfg.StaticSourcesPath,
			RedirectHTTPS:         runCfg.RedirectHTTPS,
			LandingRedirectTarget: runCfg.LandingRedirectTarget,
			TxtRecordTTL:          runCfg.TxtRecordTTL,
			AuthServiceConfig: sharing.AuthServiceConfig{
				BaseURL: runCfg.AuthService.BaseURL,
				Token:   runCfg.AuthService.Token,
				Cache: lrucache.New(
					lrucache.Options{
						Expiration: runCfg.AuthService.Cache.Expiration,
						Capacity:   runCfg.AuthService.Cache.Capacity,
					},
				),
			},
			DNSServer:            runCfg.DNSServer,
			ConnectionPool:       sharing.ConnectionPoolConfig(runCfg.ConnectionPool),
			UseQosAndCC:          runCfg.UseQosAndCC,
			ClientTrustedIPsList: runCfg.ClientTrustedIPSList,
			UseClientIPHeaders:   runCfg.UseClientIPHeaders,
		},
		GeoLocationDB: runCfg.GeoLocationDB,
	})
	if err != nil {
		return err
	}

	runError := peer.Run(ctx)
	closeError := peer.Close()

	return errs.Combine(runError, closeError)
}

func cmdSetup(cmd *cobra.Command, args []string) (err error) {
	setupDir, err := filepath.Abs(confDir)
	if err != nil {
		return err
	}

	valid, _ := fpath.IsValidSetupDir(setupDir)
	if !valid {
		return fmt.Errorf("link sharing configuration already exists (%v)", setupDir)
	}

	err = os.MkdirAll(setupDir, 0700)
	if err != nil {
		return err
	}

	return process.SaveConfig(cmd, filepath.Join(setupDir, "config.yaml"))
}

func main() {
	process.Exec(rootCmd)
}
