// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/zeebo/clingy"

	client "storj.io/gateway-mt/internal/authadminclient"
)

var logger *log.Logger

func init() {
	logger = log.New(io.Discard, "", log.LstdFlags|log.LUTC)
}

func main() {
	ok, err := clingy.Environment{}.Run(context.Background(), func(cmds clingy.Commands) {
		logEnabled := cmds.Flag("log.enabled", "log debug messages", false,
			clingy.Transform(strconv.ParseBool), clingy.Boolean,
		).(bool)
		if logEnabled {
			logger.SetOutput(os.Stderr)
		}

		cmds.Group("record", "record commands", func() {
			cmds.New("show", "show a record", new(cmdShow))
			cmds.New("invalidate", "invalidate a record", new(cmdInvalidate))
			cmds.New("unpublish", "unpublish a record", new(cmdUnpublish))
			cmds.New("delete", "delete a record", new(cmdDelete))
		})
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
	}
	if !ok || err != nil {
		os.Exit(1)
	}
}

type cmdShow struct {
	clientConfig client.Config
	key          string
	output       string
	expanded     bool
}

func (cmd *cmdShow) Setup(params clingy.Parameters) {
	setupClientConfig(params, &cmd.clientConfig)

	cmd.output = params.Flag("output", "output format (valid options: tabbed, json)", "tabbed",
		clingy.Short('o'),
	).(string)
	cmd.expanded = params.Flag("expanded", "show more record information", false,
		clingy.Short('x'),
		clingy.Transform(strconv.ParseBool), clingy.Boolean,
	).(bool)
	cmd.key = params.Arg("key", "Access key ID or key hash").(string)
}

func (cmd *cmdShow) Execute(ctx context.Context) error {
	record, err := client.New(cmd.clientConfig, logger).Get(ctx, cmd.key)
	if err != nil {
		return err
	}

	switch cmd.output {
	case "tabbed", "":
		return printTabbedRecord(record, cmd.expanded)
	case "json":
		return json.NewEncoder(os.Stdout).Encode(record)
	default:
		return fmt.Errorf("unsupported output %q (valid options: tabbed, json)", cmd.output)
	}
}

type cmdInvalidate struct {
	clientConfig client.Config
	key          string
	reason       string
}

func (cmd *cmdInvalidate) Setup(params clingy.Parameters) {
	setupClientConfig(params, &cmd.clientConfig)

	cmd.key = params.Arg("key", "Access key ID or key hash").(string)
	cmd.reason = params.Arg("reason", "invalidation reason").(string)
}

func (cmd *cmdInvalidate) Execute(ctx context.Context) error {
	return client.New(cmd.clientConfig, logger).Invalidate(ctx, cmd.key, cmd.reason)
}

type cmdUnpublish struct {
	clientConfig client.Config
	key          string
}

func (cmd *cmdUnpublish) Setup(params clingy.Parameters) {
	setupClientConfig(params, &cmd.clientConfig)

	cmd.key = params.Arg("key", "Access key ID or key hash").(string)
}

func (cmd *cmdUnpublish) Execute(ctx context.Context) error {
	return client.New(cmd.clientConfig, logger).Unpublish(ctx, cmd.key)
}

type cmdDelete struct {
	clientConfig client.Config
	key          string
}

func (cmd *cmdDelete) Setup(params clingy.Parameters) {
	setupClientConfig(params, &cmd.clientConfig)

	cmd.key = params.Arg("key", "Access key ID or key hash").(string)
}

func (cmd *cmdDelete) Execute(ctx context.Context) error {
	return client.New(cmd.clientConfig, logger).Delete(ctx, cmd.key)
}

func setupClientConfig(params clingy.Parameters, config *client.Config) {
	config.NodeAddresses = params.Flag("node-addresses", "comma delimited list of node addresses", []string{},
		clingy.Transform(func(s string) ([]string, error) {
			return strings.Split(s, ","), nil
		})).([]string)
	config.CertsDir = params.Flag("certs-dir", "directory of certificates for authentication", "").(string)
	config.InsecureDisableTLS = params.Flag("insecure-disable-tls", "disable tls for testing", false,
		clingy.Transform(strconv.ParseBool), clingy.Boolean,
	).(bool)
}

func printTabbedRecord(r *client.Record, expanded bool) error {
	w := tabwriter.NewWriter(os.Stdout, 2, 2, 2, ' ', 0)
	headers := []string{"CREATED", "PUBLIC"}
	values := []string{time.Unix(r.CreatedAtUnix, 0).UTC().Format(time.RFC3339), strconv.FormatBool(r.Public)}
	if r.ExpiresAtUnix != 0 {
		headers = append(headers, "EXPIRES")
		values = append(values, time.Unix(r.ExpiresAtUnix, 0).UTC().Format(time.RFC3339))
	}
	if r.InvalidatedAtUnix != 0 {
		headers = append(headers, "INVALIDATED")
		values = append(values, time.Unix(r.InvalidatedAtUnix, 0).UTC().Format(time.RFC3339))
	}
	if r.InvalidationReason != "" {
		headers = append(headers, "INVALIDATION REASON")
		values = append(values, r.InvalidationReason)
	}
	if expanded {
		headers = append(headers, "SATELLITE", "MACAROON HEAD")
		values = append(values, r.SatelliteAddress, r.MacaroonHeadHex)
		if r.APIKey != "" {
			headers = append(headers, "API KEY")
			values = append(values, r.APIKey)
		}
		if r.DecryptedAccessGrant != "" {
			headers = append(headers, "ACCESS GRANT")
			values = append(values, r.DecryptedAccessGrant)
		}
	}
	fmt.Fprintln(w, strings.Join(headers, "\t"))
	fmt.Fprintln(w, strings.Join(values, "\t"))
	return w.Flush()
}
