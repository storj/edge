// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"github.com/zeebo/clingy"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sync/errgroup"

	"storj.io/common/errs2"
	"storj.io/common/rpc/rpcstatus"
	"storj.io/edge/internal/authadminclient"
	"storj.io/edge/internal/satelliteadminclient"
	"storj.io/edge/pkg/auth/spannerauth"
	"storj.io/eventkit"
	"storj.io/eventkit/bigquery"
)

var (
	logger    *log.Logger
	zapLogger *zap.Logger
	ek        = eventkit.Package()
)

func init() {
	logger = log.New(io.Discard, "", log.LstdFlags|log.LUTC)
	zapLogger = zap.NewNop()
}

func main() {
	ok, err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
	}
	if !ok || err != nil {
		os.Exit(1)
	}
}

func run() (bool, error) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)

	var eg errgroup.Group

	ok, err := clingy.Environment{}.Run(ctx, func(cmds clingy.Commands) {
		logEnabled := cmds.Flag("log.enabled", "log debug messages", false,
			clingy.Transform(strconv.ParseBool), clingy.Boolean,
		).(bool)
		if logEnabled {
			zapLogger = zap.New(zapcore.NewCore(
				zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()),
				zapcore.AddSync(zapcore.AddSync(os.Stderr)),
				zap.DebugLevel,
			))
			logger.SetOutput(os.Stderr)
		}

		addr := cmds.Flag("events.addr", "address to send events to", "").(string)
		if addr != "" {
			logger.Printf("sending events to %s", addr)
			var ed eventkit.Destination = eventkit.NewUDPClient("authservice-admin", "v0.0.0", "", addr)
			if strings.HasPrefix(addr, "bigquery:") {
				var err error
				ed, err = bigquery.CreateDestination(ctx, addr)
				if err != nil {
					logger.Printf("create bigquery destination: %s", err)
					return
				}
			}
			eventkit.DefaultRegistry.AddDestination(ed)
			eg.Go(func() error {
				ed.Run(ctx)
				return nil
			})
		}

		cmds.Group("record", "record commands", func() {
			cmds.New("show", "show a record", new(cmdRecordShow))
			cmds.New("invalidate", "invalidate a record", new(cmdRecordInvalidate))
			cmds.New("unpublish", "unpublish a record", new(cmdRecordUnpublish))
			cmds.New("delete", "delete a record", new(cmdRecordDelete))
			cmds.New("sync", "sync records with satellite database", new(cmdRecordSync))
		})
		cmds.Group("links", "links commands", func() {
			cmds.New("inspect", "inspect given links and return a report", new(cmdLinksInspect))
			cmds.New("revoke", "revoke access for given links", new(cmdLinksRevoke))
		})
	})

	stop()

	// wait for event collector to shut down after context cancelled.
	// no errors are returned, so there's no need to check.
	_ = eg.Wait()

	return ok, err
}

func getAuthAdminClientConfig(params clingy.Parameters) authadminclient.Config {
	return authadminclient.Config{
		Spanner: spannerauth.Config{
			DatabaseName:        params.Flag("storage.spanner.db-name", "name of Cloud Spanner database in the form projects/PROJECT_ID/instances/INSTANCE_ID/databases/DATABASE_ID", "").(string),
			CredentialsFilename: params.Flag("storage.spanner.creds", "credentials file with access to Cloud Spanner database", "").(string),
		},
	}
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
		clients[parts[0]] = satelliteadminclient.New(parts[1], parts[2], logger)
	}
	return nil
}

func satAPIKeyError(err error) error {
	if errs.Is(err, satelliteadminclient.ErrNotFound) {
		return errs.New("api key not found on satellite. It may have already been deleted")
	}
	return err
}

func authAccessKeyError(err error) error {
	if errs2.IsRPC(err, rpcstatus.NotFound) {
		return errs.New("access key not found on authservice. It may have already been deleted")
	}
	return err
}
