// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	minio "github.com/minio/minio/cmd"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/fpath"
	"storj.io/common/rpc/rpcpool"
	"storj.io/gateway-mt/pkg/server"
	"storj.io/gateway-mt/pkg/trustedip"
	"storj.io/private/cfgstruct"
	"storj.io/private/process"
	"storj.io/uplink"
)

// GatewayFlags configuration flags.
type GatewayFlags struct {
	Server server.Config

	AuthURL              string   `help:"Auth Service endpoint URL to return to clients" releaseDefault:"" devDefault:"http://localhost:8000"`
	AuthToken            string   `help:"Auth Service security token to authenticate requests" releaseDefault:"" devDefault:"super-secret"`
	CertDir              string   `help:"directory path to search for TLS certificates" default:"$CONFDIR/certs"`
	InsecureDisableTLS   bool     `help:"listen using insecure connections" releaseDefault:"false" devDefault:"true"`
	DomainName           string   `help:"comma-separated domain suffixes to serve on" releaseDefault:"" devDefault:"localhost"`
	CorsOrigins          string   `help:"list of domains (comma separated) other than the gateway's domain, from which a browser should permit loading resources requested from the gateway" default:"*"`
	EncodeInMemory       bool     `help:"tells libuplink to perform in-memory encoding on file upload" releaseDefault:"true" devDefault:"true"`
	ClientTrustedIPSList []string `help:"list of clients IPs (without port and comma separated) which are trusted; usually used when the service run behinds gateways, load balancers, etc."`
	UseClientIPHeaders   bool     `help:"use the headers sent by the client to identify its IP. When true the list of IPs set by --client-trusted-ips-list, when not empty, is used" default:"true"`
	InsecureLogAll       bool     `help:"insecurely log all errors, paths, and headers" default:"false"`

	S3Compatibility server.S3CompatibilityConfig

	Config
	ConnectionPool ConnectionPoolConfig
}

// ConnectionPoolConfig is a config struct for configuring RPC connection pool options.
type ConnectionPoolConfig struct {
	Capacity       int           `help:"RPC connection pool capacity" default:"100"`
	KeyCapacity    int           `help:"RPC connection pool key capacity" default:"5"`
	IdleExpiration time.Duration `help:"RPC connection pool idle expiration" default:"2m0s"`
}

// ClientConfig is a configuration struct for the uplink that controls how
// to talk to the rest of the network.
type ClientConfig struct {
	DialTimeout time.Duration `help:"timeout for dials" default:"0h2m00s"`
	UseQosAndCC bool          `help:"use congestion control and QOS settings" default:"true"`
}

// Config uplink configuration.
type Config struct {
	Client ClientConfig
}

var (
	// Error is the default gateway setup errs class.
	Error = errs.Class("gateway setup")
	// rootCmd represents the base gateway command when called without any subcommands.
	rootCmd = &cobra.Command{
		Use:   "gateway",
		Short: "The Storj client-side S3 gateway",
		Args:  cobra.OnlyValidArgs,
	}
	runCmd = &cobra.Command{
		Use:   "run",
		Short: "Run the classic S3-compatible gateway",
		RunE:  cmdRun,
	}
	runCfg GatewayFlags

	confDir string
)

func init() {
	defaultConfDir := fpath.ApplicationDir("storj", "gateway")
	cfgstruct.SetupFlag(zap.L(), rootCmd, &confDir, "config-dir", defaultConfDir, "main directory for gateway configuration")
	defaults := cfgstruct.DefaultsFlag(rootCmd)

	rootCmd.AddCommand(runCmd)
	process.Bind(runCmd, &runCfg, defaults, cfgstruct.ConfDir(confDir))

	// The loop below sets all flags in GatewayFlags to show up without the
	// `--advanced` flag until we decide which flags we want to hide.
	runCmd.Flags().VisitAll(func(f *pflag.Flag) {
		cfgstruct.SetBoolAnnotation(runCmd.Flags(), f.Name, cfgstruct.BasicHelpAnnotationName, true)
	})

	rootCmd.PersistentFlags().BoolVar(new(bool), "advanced", false, "if used in with -h, print advanced flags help")
	cfgstruct.SetBoolAnnotation(rootCmd.PersistentFlags(), "advanced", cfgstruct.BasicHelpAnnotationName, true)
	cfgstruct.SetBoolAnnotation(rootCmd.PersistentFlags(), "config-dir", cfgstruct.BasicHelpAnnotationName, true)
	setUsageFunc(rootCmd)
}

func cmdRun(cmd *cobra.Command, args []string) (err error) {
	address := runCfg.Server.Address
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if host == "" {
		address = net.JoinHostPort("127.0.0.1", port)
	}

	ctx, _ := process.Ctx(cmd)

	if err := process.InitMetricsWithHostname(ctx, zap.L(), nil); err != nil {
		zap.S().Warn("Failed to initialize telemetry batcher: ", err)
	}

	// setup environment variables for Minio
	validate := func(value, configName string) {
		if value == "" {
			err = errs.Combine(err, Error.New("required parameter --%s not set", configName))
		}
	}
	set := func(value, envName string) {
		err = errs.Combine(err, Error.Wrap(os.Setenv(envName, value)))
	}
	validate(runCfg.AuthToken, "auth-token")
	validate(runCfg.AuthURL, "auth-url")
	validate(runCfg.DomainName, "domain-name")
	set(runCfg.DomainName, "MINIO_DOMAIN") // MINIO_DOMAIN supports comma-separated domains.
	set("enable", "STORJ_AUTH_ENABLED")
	set("off", "MINIO_BROWSER")
	set("dummy-key-to-satisfy-minio", "MINIO_ACCESS_KEY")
	set("dummy-key-to-satisfy-minio", "MINIO_SECRET_KEY")
	if err != nil {
		return err
	}

	return runCfg.Run(ctx, address)
}

// Run starts a Minio Gateway given proper config.
func (flags GatewayFlags) Run(ctx context.Context, address string) (err error) {
	// set object API handler
	gatewayLayer, err := flags.NewGateway(ctx)
	if err != nil {
		return err
	}

	minio.StartMinio(address, runCfg.AuthURL, runCfg.AuthToken, gatewayLayer, strings.Split(runCfg.CorsOrigins, ","))

	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}

	zap.S().Info("Starting Storj DCS S3 Gateway")
	zap.S().Infof("Endpoint: %s", address)

	if runCfg.InsecureLogAll {
		zap.S().Info("Insecurely logging all errors, paths, and headers")
	}

	// because existing configs contain most of these values, we don't have separate
	// parameter bindings for the non-Minio server
	var tlsConfig *tls.Config
	if !runCfg.InsecureDisableTLS {
		tlsConfig, err = server.LoadTLSConfigFromDir(runCfg.CertDir)
		if err != nil {
			return err
		}
	}

	var trustedClientIPs trustedip.List

	if runCfg.UseClientIPHeaders {
		if len(runCfg.ClientTrustedIPSList) > 0 {
			trustedClientIPs = trustedip.NewList(runCfg.ClientTrustedIPSList...)
		} else {
			trustedClientIPs = trustedip.NewListTrustAll()
		}
	} else {
		trustedClientIPs = trustedip.NewListUntrustAll()
	}

	s3 := server.New(listener, zap.L(), tlsConfig, runCfg.EncodeInMemory, trustedClientIPs, runCfg.InsecureLogAll)
	runError := s3.Run(ctx)
	closeError := s3.Close()
	return errs.Combine(runError, closeError)
}

// NewGateway creates a new minio Gateway.
func (flags GatewayFlags) NewGateway(ctx context.Context) (gw minio.ObjectLayer, err error) {
	config := flags.newUplinkConfig(ctx)
	pool := rpcpool.New(rpcpool.Options(flags.ConnectionPool))

	return server.NewGateway(config, pool, flags.S3Compatibility, flags.InsecureLogAll)
}

func (flags *GatewayFlags) newUplinkConfig(ctx context.Context) uplink.Config {
	// Transform the gateway config flags to the uplink config object
	config := uplink.Config{}
	config.DialTimeout = flags.Client.DialTimeout
	if !flags.Client.UseQosAndCC {
		// an unset DialContext defaults to BackgroundDialer's CC and QOS settings
		config.DialContext = (&net.Dialer{}).DialContext
	}
	return config
}

/*	`setUsageFunc` is a bit unconventional but cobra didn't leave much room for
	extensibility here. `cmd.SetUsageTemplate` is fairly useless for our case without
	the ability to add to the template's function map (see: https://golang.org/pkg/text/template/#hdr-Functions).

	Because we can't alter what `cmd.Usage` generates, we have to edit it afterwards.
	In order to hook this function *and* get the usage string, we have to juggle the
	`cmd.usageFunc` between our hook and `nil`, so that we can get the usage string
	from the default usage func.
*/
func setUsageFunc(cmd *cobra.Command) {
	if findBoolFlagEarly("advanced") {
		return
	}

	reset := func() (set func()) {
		original := cmd.UsageFunc()
		cmd.SetUsageFunc(nil)

		return func() {
			cmd.SetUsageFunc(original)
		}
	}

	cmd.SetUsageFunc(func(cmd *cobra.Command) error {
		set := reset()
		usageStr := cmd.UsageString()
		defer set()

		usageScanner := bufio.NewScanner(bytes.NewBufferString(usageStr))

		var basicFlags []string
		cmd.Flags().VisitAll(func(flag *pflag.Flag) {
			basic, ok := flag.Annotations[cfgstruct.BasicHelpAnnotationName]
			if ok && len(basic) == 1 && basic[0] == "true" {
				basicFlags = append(basicFlags, flag.Name)
			}
		})

		for usageScanner.Scan() {
			line := usageScanner.Text()
			trimmedLine := strings.TrimSpace(line)

			var flagName string
			if _, err := fmt.Sscanf(trimmedLine, "--%s", &flagName); err != nil {
				fmt.Println(line)
				continue
			}

			// TODO: properly filter flags with short names
			if !strings.HasPrefix(trimmedLine, "--") {
				fmt.Println(line)
			}

			for _, basicFlag := range basicFlags {
				if basicFlag == flagName {
					fmt.Println(line)
				}
			}
		}
		return nil
	})
}

func findBoolFlagEarly(flagName string) bool {
	for i, arg := range os.Args {
		arg := arg
		argHasPrefix := func(format string, args ...interface{}) bool {
			return strings.HasPrefix(arg, fmt.Sprintf(format, args...))
		}

		if !argHasPrefix("--%s", flagName) {
			continue
		}

		// NB: covers `--<flagName> false` usage
		if i+1 != len(os.Args) {
			next := os.Args[i+1]
			if next == "false" {
				return false
			}
		}

		if !argHasPrefix("--%s=false", flagName) {
			return true
		}
	}
	return false
}

func main() {
	process.Exec(rootCmd)
}
