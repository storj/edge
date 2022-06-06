// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"storj.io/common/grant"
	"storj.io/gateway-mt/pkg/authclient"
	"storj.io/private/cfgstruct"
	"storj.io/private/process"
)

var config struct {
	AuthServiceBaseURL string `default:"" help:"authservice base url"`
	AuthServiceToken   string `default:"" help:"authservice token"`
}

func main() {
	cmd := &cobra.Command{
		Use:  "authservice-lookup-util [access-key]",
		RunE: cmdRun,
		Args: cobra.ExactArgs(1),
	}
	process.Bind(cmd, &config, cfgstruct.DefaultsFlag(cmd))
	process.Exec(cmd)
}

func cmdRun(cmd *cobra.Command, args []string) (err error) {
	ctx, cancel := process.Ctx(cmd)
	defer cancel()

	authService := authclient.AuthClient{Config: authclient.Config{
		BaseURL: config.AuthServiceBaseURL,
		Token:   config.AuthServiceToken,
	}}
	resp, err := authService.Resolve(ctx, args[0], "0.0.0.0")
	if err != nil {
		return err
	}
	ag, err := grant.ParseAccess(resp.AccessGrant)
	if err != nil {
		return err
	}

	_, err = fmt.Printf(`public: %v
access grant: %q
satellite: %q
api key: %q
`,
		resp.Public,
		resp.AccessGrant,
		ag.SatelliteAddress,
		ag.APIKey.Serialize(),
	)

	return err
}
