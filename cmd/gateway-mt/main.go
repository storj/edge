// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/minio/cli"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	minio "github.com/storj/minio/cmd"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/fpath"
	"storj.io/common/rpc"
	"storj.io/gateway-mt/internal/wizard"
	"storj.io/gateway-mt/miniogw"
	"storj.io/gateway-mt/pkg/server"
	"storj.io/private/cfgstruct"
	"storj.io/private/process"
	"storj.io/uplink"
)

// GatewayFlags configuration flags.
type GatewayFlags struct {
	Server miniogw.ServerConfig
	Minio  miniogw.MinioConfig

	MultipartUploadSatellites []string `help:"satellite addresses that has multipart-upload enabled" default:"" basic-help:"true"`
	AuthURL                   string   `help:"Auth Service endpoint URL to return to clients" releaseDefault:"" devDefault:"http://localhost:8000" basic-help:"true"`
	AuthToken                 string   `help:"Auth Service security token to authenticate requests" releaseDefault:"" devDefault:"super-secret" basic-help:"true"`
	DomainName                string   `help:"base domain name used in TLS certificates" releaseDefault:"" devDefault:"localhost" basic-help:"true"`
	Config
}

// ClientConfig is a configuration struct for the uplink that controls how
// to talk to the rest of the network.
type ClientConfig struct {
	DialTimeout time.Duration `help:"timeout for dials" default:"0h2m00s"`
}

// Config uplink configuration.
type Config struct {
	Client ClientConfig
}

var (
	// Error is the default gateway setup errs class.
	Error = errs.Class("gateway setup error")
	// rootCmd represents the base gateway command when called without any subcommands.
	rootCmd = &cobra.Command{
		Use:   "gateway",
		Short: "The Storj client-side S3 gateway",
		Args:  cobra.OnlyValidArgs,
	}
	setupCmd = &cobra.Command{
		Use:         "setup",
		Short:       "Create a gateway config file",
		RunE:        cmdSetup,
		Annotations: map[string]string{"type": "setup"},
	}
	runCmd = &cobra.Command{
		Use:   "run",
		Short: "Run the classic S3-compatible gateway",
		RunE:  cmdRun,
	}
	runNewCmd = &cobra.Command{
		Use:   "runNew",
		Short: "Run the new S3-compatible gateway",
		RunE:  cmdRunNew,
	}
	setupCfg GatewayFlags
	runCfg   GatewayFlags

	confDir string
)

func init() {
	defaultConfDir := fpath.ApplicationDir("storj", "gateway")
	cfgstruct.SetupFlag(zap.L(), rootCmd, &confDir, "config-dir", defaultConfDir, "main directory for gateway configuration")
	defaults := cfgstruct.DefaultsFlag(rootCmd)

	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(runNewCmd)
	rootCmd.AddCommand(setupCmd)
	process.Bind(runCmd, &runCfg, defaults, cfgstruct.ConfDir(confDir))
	process.Bind(setupCmd, &setupCfg, defaults, cfgstruct.ConfDir(confDir), cfgstruct.SetupMode())

	rootCmd.PersistentFlags().BoolVar(new(bool), "advanced", false, "if used in with -h, print advanced flags help")
	cfgstruct.SetBoolAnnotation(rootCmd.PersistentFlags(), "advanced", cfgstruct.BasicHelpAnnotationName, true)
	cfgstruct.SetBoolAnnotation(rootCmd.PersistentFlags(), "config-dir", cfgstruct.BasicHelpAnnotationName, true)
	setUsageFunc(rootCmd)
}

func cmdSetup(cmd *cobra.Command, args []string) (err error) {
	setupDir, err := filepath.Abs(confDir)
	if err != nil {
		return Error.Wrap(err)
	}

	valid, _ := fpath.IsValidSetupDir(setupDir)
	if !valid {
		return Error.New("gateway configuration already exists (%v)", setupDir)
	}

	err = os.MkdirAll(setupDir, 0700)
	if err != nil {
		return Error.Wrap(err)
	}

	return setupCfg.interactive(cmd, setupDir)
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

	if err := process.InitMetrics(ctx, zap.L(), nil, ""); err != nil {
		zap.S().Warn("Failed to initialize telemetry batcher: ", err)
	}

	// setup environment variables for Minio
	validateAndSet := func(value, configName, envName string) {
		if value == "" {
			err = errs.Combine(err, Error.New("required parameter --%s not set", configName))
			return
		}
		err = errs.Combine(err, Error.Wrap(os.Setenv(envName, value)))
	}
	validateAndSet(runCfg.AuthToken, "auth-token", "MINIO_STORJ_AUTH_TOKEN")
	validateAndSet(runCfg.AuthURL, "auth-url", "MINIO_STORJ_AUTH_URL")
	validateAndSet(runCfg.DomainName, "domain-name", "MINIO_DOMAIN")
	validateAndSet("enable", "n/a", "STORJ_AUTH_ENABLED")
	validateAndSet("off", "n/a", "MINIO_BROWSER")
	validateAndSet("dummy-key-to-satisfy-minio", "n/a", "MINIO_ACCESS_KEY")
	validateAndSet("dummy-key-to-satisfy-minio", "n/a", "MINIO_SECRET_KEY")
	if err != nil {
		return err
	}

	zap.S().Info("Starting Tardigrade S3 Gateway\n\n")
	zap.S().Infof("Endpoint: %s\n", address)
	zap.S().Info("Access key: use your Tardigrade Access Grant\n")
	zap.S().Info("Secret key: anything would work\n")

	return runCfg.Run(ctx)
}

// Run starts a Minio Gateway given proper config.
func (flags GatewayFlags) Run(ctx context.Context) (err error) {
	err = minio.RegisterGatewayCommand(cli.Command{
		Name:  "storj",
		Usage: "Storj",
		Action: func(cliCtx *cli.Context) error {
			return flags.action(ctx, cliCtx)
		},
		HideHelpCommand: true,
	})
	if err != nil {
		return err
	}

	minio.Main([]string{"storj", "gateway", "storj",
		"--address", flags.Server.Address, "--config-dir", flags.Minio.Dir, "--quiet",
		"--compat"})
	return errs.New("unexpected minio exit")
}

func cmdRunNew(cmd *cobra.Command, args []string) (err error) {
	address := runCfg.Server.Address
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if host == "" {
		address = net.JoinHostPort("127.0.0.1", port)
	}

	ctx, _ := process.Ctx(cmd)

	if err := process.InitMetrics(ctx, zap.L(), nil, ""); err != nil {
		zap.S().Warn("Failed to initialize telemetry batcher: ", err)
	}

	// setup environment variables for Minio
	if runCfg.AuthToken == "" {
		err = errs.Combine(err, Error.New("required parameter --auth-token not set"))
	}
	if runCfg.AuthURL == "" {
		err = errs.Combine(err, Error.New("required parameter --auth-url not set"))
	}
	if runCfg.DomainName == "" {
		err = errs.Combine(err, Error.New("required parameter --domain-name not set"))
	}
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}

	zap.S().Info("Starting Tardigrade S3 Gateway\n\n")
	zap.S().Infof("Endpoint: %s\n", address)
	zap.S().Info("Access key: use your Tardigrade Access Grant\n")
	zap.S().Info("Secret key: anything would work\n")

	s3 := server.New(listener, zap.L(), runCfg.DomainName)
	runError := s3.Run(ctx)
	closeError := s3.Close()
	return errs.Combine(runError, closeError)
}

func (flags GatewayFlags) action(ctx context.Context, cliCtx *cli.Context) (err error) {
	gw, err := flags.NewGateway(ctx)
	if err != nil {
		return err
	}

	minio.StartGateway(cliCtx, miniogw.Logging(gw, zap.L()))
	return errs.New("unexpected minio exit")
}

// NewGateway creates a new minio Gateway.
func (flags GatewayFlags) NewGateway(ctx context.Context) (gw minio.Gateway, err error) {
	config := flags.newUplinkConfig(ctx)
	multipartSatAddrs := flags.MultipartUploadSatellites
	addrs, err := miniogw.RemoveNodeIDs(multipartSatAddrs)
	if err != nil {
		return nil, err
	}
	pool := rpc.NewDefaultConnectionPool()

	return miniogw.NewStorjGateway(config, pool, addrs), nil
}

func (flags *GatewayFlags) newUplinkConfig(ctx context.Context) uplink.Config {
	// Transform the gateway config flags to the uplink config object
	config := uplink.Config{}
	config.DialTimeout = flags.Client.DialTimeout
	return config
}

// interactive creates the configuration of the gateway interactively.
func (flags GatewayFlags) interactive(cmd *cobra.Command, setupDir string) error {
	overrides := make(map[string]interface{})

	tracingEnabled, err := wizard.PromptForTracing()
	if err != nil {
		return Error.Wrap(err)
	}
	if tracingEnabled {
		overrides["tracing.enabled"] = true
		overrides["tracing.sample"] = 0.1
		overrides["tracing.interval"] = 30 * time.Second
	}

	err = process.SaveConfig(cmd, filepath.Join(setupDir, "config.yaml"),
		process.SaveConfigWithOverrides(overrides),
		process.SaveConfigRemovingDeprecated())
	if err != nil {
		return Error.Wrap(err)
	}

	fmt.Println(`
Your S3 Gateway is configured and ready to use!

Some things to try next:

* See https://documentation.tardigrade.io/api-reference/s3-gateway for some example commands`)

	return nil
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
