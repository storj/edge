// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/zeebo/clingy"

	"storj.io/gateway-mt/internal/authadminclient"
	"storj.io/gateway-mt/internal/satelliteadminclient"
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
			cmds.New("show", "show a record", new(cmdRecordShow))
			cmds.New("invalidate", "invalidate a record", new(cmdRecordInvalidate))
			cmds.New("unpublish", "unpublish a record", new(cmdRecordUnpublish))
			cmds.New("delete", "delete a record", new(cmdRecordDelete))
		})
		cmds.Group("links", "links commands", func() {
			cmds.New("inspect", "inspect given links and return a report", new(cmdLinksInspect))
			cmds.New("revoke", "revoke access for given links", new(cmdLinksRevoke))
		})
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
	}
	if !ok || err != nil {
		os.Exit(1)
	}
}

func newAuthAdminClient(params clingy.Parameters) *authadminclient.AuthAdminClient {
	return authadminclient.New(authadminclient.Config{
		NodeAddresses: params.Flag("node-addresses", "comma delimited list of authservice node addresses", []string{},
			clingy.Transform(func(s string) ([]string, error) {
				return strings.Split(s, ","), nil
			})).([]string),
		CertsDir: params.Flag("certs-dir", "directory of certificates for authentication with authservice nodes", "").(string),
	}, logger)
}

func mustSatAdminClients(params clingy.Parameters) map[string]*satelliteadminclient.Client {
	values := params.Flag("satellite-admin-addresses", "comma delimited list of satellite admin addresses, e.g. us1.storj.io:7777=http://localhost:10005=123,eu1.storj.io:7777=http://localhost:10006=456", []string{},
		clingy.Transform(func(s string) ([]string, error) {
			return strings.Split(s, ","), nil
		})).([]string)

	if len(values) == 0 {
		return nil
	}

	clients := make(map[string]*satelliteadminclient.Client)
	if err := loadSatAdminClients(clients, values); err != nil {
		panic(err)
	}

	return clients
}

func loadSatAdminClients(clients map[string]*satelliteadminclient.Client, values []string) error {
	for _, value := range values {
		parts := strings.Split(value, "=")
		if len(parts) != 3 {
			return fmt.Errorf("invalid satellite mapping %q", value)
		}
		clients[parts[0]] = satelliteadminclient.New(parts[1], parts[2])
	}
	return nil
}
