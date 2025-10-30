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
	"golang.org/x/sync/errgroup"

	"storj.io/common/cfgstruct"
	"storj.io/common/errs2"
	"storj.io/common/fpath"
	"storj.io/common/identity"
	"storj.io/common/process"
	"storj.io/edge/pkg/authclient"
	"storj.io/edge/pkg/httpserver"
	"storj.io/edge/pkg/linksharing"
	"storj.io/edge/pkg/linksharing/sharing"
	"storj.io/edge/pkg/linksharing/sharing/assets"
	"storj.io/edge/pkg/tierquery"
	"storj.io/edge/pkg/uplinkutil"
	"storj.io/uplink"
)

// LinkSharing defines link sharing configuration.
//
// TODO(artur): some of these options could be grouped, e.g. into Security.
type LinkSharing struct {
	Address                string        `user:"true" help:"public address to listen on" default:":20020"`
	AddressTLS             string        `user:"true" help:"public tls address to listen on" default:":20021"`
	ProxyAddressTLS        string        `user:"true" help:"tls address to listen on for PROXY protocol requests" default:":20022"`
	InsecureDisableTLS     bool          `user:"true" help:"listen using insecure connections only" releaseDefault:"false" devDefault:"true"`
	CertFile               string        `user:"true" help:"server certificate file"`
	KeyFile                string        `user:"true" help:"server key file"`
	PublicURL              string        `user:"true" help:"comma separated list of public urls for the server" devDefault:"http://localhost:20020" releaseDefault:""`
	GeoLocationDB          string        `user:"true" help:"maxmind database file path"`
	TXTRecordTTL           time.Duration `user:"true" help:"max ttl (seconds) for website hosting txt record cache" devDefault:"10s" releaseDefault:"1h"`
	AuthService            authclient.Config
	DNSServer              string        `user:"true" help:"dns server address to use for TXT resolution" default:"1.1.1.1:53"`
	LandingRedirectTarget  string        `user:"true" help:"the url to redirect empty requests to" default:"https://www.storj.io/"`
	RedirectHTTPS          bool          `user:"true" help:"redirect to HTTPS" devDefault:"false" releaseDefault:"true"`
	DialTimeout            time.Duration `help:"timeout for dials" default:"10s"`
	IdleTimeout            time.Duration `help:"timeout for idle connections" default:"60s"`
	ClientTrustedIPSList   []string      `user:"true" help:"list of clients IPs (comma separated) which are trusted; usually used when the service run behinds gateways, load balancers, etc."`
	UseClientIPHeaders     bool          `user:"true" help:"use the headers sent by the client to identify its IP. When true the list of IPs set by --client-trusted-ips-list, when not empty, is used" default:"true"`
	StandardRendersContent bool          `user:"true" help:"enable standard (non-hosting) requests to render content and not only download it" default:"false"`
	StandardViewsHTML      bool          `user:"true" help:"serve HTML as text/html instead of text/plain for standard (non-hosting) requests" default:"false"`
	ListPageLimit          int           `help:"maximum number of paths to list on a single page" default:"100"`
	DownloadPrefixEnabled  bool          `help:"whether downloading a prefix as a zip or tar file is enabled" default:"false"`
	DownloadZipLimit       int           `help:"maximum number of files from a prefix that can be packaged into a downloadable zip" default:"1000"`
	DynamicAssetsDir       string        `help:"use a assets dir that is reparsed for every request" default:""`
	BlockedPaths           string        `help:"a comma separated list of hosts and request uris to return unauthorized errors for. e.g. link.storjshare.io/raw/accesskey/bucket/path1"`
	TracingAnnotations     []string      `user:"true" help:"list of annotations which are supported by distributed tracing" default:"checkerng,test,placement"`

	Client struct {
		Identity uplinkutil.IdentityConfig
	}

	SatelliteConnectionPool satelliteConnectionPoolConfig
	ConnectionPool          connectionPoolConfig
	Limits                  limitsConfig

	CertMagic     certMagic
	ShutdownDelay time.Duration `user:"true" help:"time to delay server shutdown while returning 503s on the health endpoint" devDefault:"1s" releaseDefault:"45s"`
	StartupCheck  startupCheck
}

// connectionPoolConfig is a config struct for configuring RPC connection pool options.
type connectionPoolConfig struct {
	Capacity       int           `user:"true" help:"RPC connection pool capacity" default:"100"`
	KeyCapacity    int           `user:"true" help:"RPC connection pool key capacity" default:"5"`
	IdleExpiration time.Duration `user:"true" help:"RPC connection pool idle expiration" default:"2m0s"`
	MaxLifetime    time.Duration `help:"RPC connection pool max lifetime of a connection" default:"10m0s"`
}

// satelliteConnectionPoolConfig is a config struct for configuring RPC connection pool of Satellite connections.
type satelliteConnectionPoolConfig struct {
	Capacity       int           `help:"RPC connection pool capacity (satellite connections)" default:"200"`
	KeyCapacity    int           `help:"RPC connection pool limit per key (satellite connections)" default:"0"`
	IdleExpiration time.Duration `help:"RPC connection pool idle expiration (satellite connections)" default:"10m0s"`
	MaxLifetime    time.Duration `help:"RPC connection pool max lifetime of a connection" default:"10m0s"`
}

// limitsConfig is a config struct for configuring request limiting behavior.
type limitsConfig struct {
	ConcurrentRequests uint `help:"the number of concurrent requests allowed per project ID, or if unavailable, macaroon head" default:"500"`
}

// certMagic is a config struct for configuring CertMagic options.
type certMagic struct {
	Enabled               bool   `user:"true" help:"use CertMagic to handle TLS certificates" default:"false"`
	KeyFile               string `user:"true" help:"path to the service account key file"`
	Email                 string `user:"true" help:"email address to use when creating an ACME account"`
	Staging               bool   `user:"true" help:"use staging CA endpoints" devDefault:"true" releaseDefault:"false"`
	Bucket                string `user:"true" help:"bucket to use for certificate storage with optional prefix (bucket/prefix)"`
	TierServiceIdentity   identity.Config
	TierCacheExpiration   time.Duration `user:"true" help:"expiration time for tier querying service cache" devDefault:"10s" releaseDefault:"5m"`
	TierCacheCapacity     int           `user:"true" help:"tier querying service cache capacity" default:"10000"`
	SkipPaidTierAllowlist []string      `user:"true" help:"comma separated list of domain names which bypass paid tier queries. Set to * to disable tier check entirely"`
}

type startupCheck struct {
	Enabled    bool          `user:"true" help:"whether to check for satellite connectivity before starting" default:"true"`
	Satellites []string      `user:"true" help:"list of satellite NodeURLs" default:"https://www.storj.io/dcs-satellites"`
	Timeout    time.Duration `user:"true" help:"maximum time to spend on checks" default:"30s"`
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
	ctx, cancel := process.Ctx(cmd)
	defer cancel()

	log := zap.L()

	if err := process.InitMetricsWithHostname(ctx, log, nil); err != nil {
		return errs.New("failed to initialize telemetry batcher: %w", err)
	}

	publicURLs := strings.Split(runCfg.PublicURL, ",")

	assets := assets.FS()
	dynamicAssets := false
	if runCfg.DynamicAssetsDir != "" {
		assets = os.DirFS(runCfg.DynamicAssetsDir)
		dynamicAssets = true
	}

	clientCertPEM, clientKeyPEM, err := runCfg.Client.Identity.LoadPEMs()
	if err != nil {
		return err
	}

	var tlsConfig *httpserver.TLSConfig
	if !runCfg.InsecureDisableTLS {
		tlsConfig = &httpserver.TLSConfig{
			CertMagic:        runCfg.CertMagic.Enabled,
			CertMagicKeyFile: runCfg.CertMagic.KeyFile,
			CertMagicEmail:   runCfg.CertMagic.Email,
			CertMagicStaging: runCfg.CertMagic.Staging,
			CertMagicBucket:  runCfg.CertMagic.Bucket,
			TierService: tierquery.Config{
				Identity:        runCfg.CertMagic.TierServiceIdentity,
				CacheExpiration: runCfg.CertMagic.TierCacheExpiration,
				CacheCapacity:   runCfg.CertMagic.TierCacheCapacity,
			},
			SkipPaidTierAllowlist: runCfg.CertMagic.SkipPaidTierAllowlist,
			CertFile:              runCfg.CertFile,
			KeyFile:               runCfg.KeyFile,
			CertMagicPublicURLs:   publicURLs,
			ConfigDir:             confDir,
			Ctx:                   ctx,
		}
	}

	peer, err := linksharing.New(log, linksharing.Config{
		Server: httpserver.Config{
			Name:               "Link Sharing",
			Address:            runCfg.Address,
			AddressTLS:         runCfg.AddressTLS,
			ProxyAddressTLS:    runCfg.ProxyAddressTLS,
			TrafficLogging:     true,
			TLSConfig:          tlsConfig,
			ShutdownTimeout:    -1,
			IdleTimeout:        runCfg.IdleTimeout,
			StartupCheckConfig: httpserver.StartupCheckConfig(runCfg.StartupCheck),
		},
		Handler: sharing.Config{
			Assets:                  assets,
			DynamicAssets:           dynamicAssets,
			URLBases:                publicURLs,
			RedirectHTTPS:           runCfg.RedirectHTTPS,
			LandingRedirectTarget:   runCfg.LandingRedirectTarget,
			TXTRecordTTL:            runCfg.TXTRecordTTL,
			AuthServiceConfig:       runCfg.AuthService,
			DNSServer:               runCfg.DNSServer,
			SatelliteConnectionPool: sharing.ConnectionPoolConfig(runCfg.SatelliteConnectionPool),
			ConnectionPool:          sharing.ConnectionPoolConfig(runCfg.ConnectionPool),
			ClientTrustedIPsList:    runCfg.ClientTrustedIPSList,
			UseClientIPHeaders:      runCfg.UseClientIPHeaders,
			StandardViewsHTML:       runCfg.StandardViewsHTML,
			StandardRendersContent:  runCfg.StandardRendersContent,
			Uplink: &uplink.Config{
				UserAgent:   "linksharing",
				DialTimeout: runCfg.DialTimeout,
				ChainPEM:    clientCertPEM,
				KeyPEM:      clientKeyPEM,
			},
			ListPageLimit:         runCfg.ListPageLimit,
			BlockedPaths:          strings.Split(runCfg.BlockedPaths, ","),
			DownloadPrefixEnabled: runCfg.DownloadPrefixEnabled,
			DownloadZipLimit:      runCfg.DownloadZipLimit,
		},
		ConcurrentRequestLimit: runCfg.Limits.ConcurrentRequests,
		GeoLocationDB:          runCfg.GeoLocationDB,
		ShutdownDelay:          runCfg.ShutdownDelay,
		TracingAnnotations:     runCfg.TracingAnnotations,
	})
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
