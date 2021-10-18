// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/fpath"
	"storj.io/gateway-mt/pkg/authclient"
	"storj.io/gateway-mt/pkg/server"
	"storj.io/gateway-mt/pkg/trustedip"
	"storj.io/private/cfgstruct"
	"storj.io/private/process"
)

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
	runCfg server.Config

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

	corsAllowedOrigins := strings.Split(runCfg.CorsOrigins, ",")
	authURL, err := url.Parse(runCfg.AuthURL)
	if err != nil {
		return err
	}
	authClient, err := authclient.New(authURL, runCfg.AuthToken, 5*time.Minute)
	if err != nil {
		return err
	}
	s3, err := server.New(runCfg, zap.L(), tlsConfig, trustedClientIPs, corsAllowedOrigins, authClient)
	if err != nil {
		return err
	}
	runError := s3.Run()
	closeError := s3.Close()
	return errs.Combine(runError, closeError)
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
