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

	"storj.io/common/errs2"
	"storj.io/common/rpc/rpcstatus"
	"storj.io/edge/internal/authadminclient"
	"storj.io/edge/internal/satelliteadminclient"
	"storj.io/edge/pkg/auth/sqlauth"
	"storj.io/edge/pkg/eventkitotel"
	"storj.io/eventkit"
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

	// set when the event destination cannot be created: the callback cannot
	// return an error, and the failure must not be swallowed.
	var eventsErr error

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

		addr := cmds.Flag("events.addr", "address(es) to send events to: "+eventkitotel.Prefix+"host:port for an OTLP/HTTP collector, "+eventkitotel.SecurePrefix+"host:port for the same over TLS, or a bare host:port for eventkitd over UDP", "").(string)
		if addr != "" {
			// zapLogger discards everything unless --log.enabled is given, so a
			// broken destination has to come back as an error, otherwise the
			// command would keep running with the events silently dropped.
			if err := eventkitotel.Setup(ctx, zapLogger, addr, eventkit.DefaultRegistry, "authservice-admin", ""); err != nil {
				eventsErr = errs.New("failed to send events to %s: %v", addr, err)
				return
			}
			logger.Printf("sending events to %s", addr)
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

	stop()

	// flush the events collected so far after the context was cancelled.
	eventkitotel.Shutdown(zapLogger)

	if eventsErr != nil {
		return false, eventsErr
	}

	return ok, err
}

func getAuthAdminClientConfig(params clingy.Parameters) authadminclient.Config {
	return authadminclient.Config{
		SQL: sqlauth.Config{
			URL: params.Flag("storage.sql.url", "connection URL to SQL database", "").(string),
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
