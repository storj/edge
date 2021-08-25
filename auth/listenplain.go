// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package auth

import (
	"context"
	"errors"
	"net"
	"net/http"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"storj.io/common/pb"
	"storj.io/drpc/drpcmigrate"
	"storj.io/gateway-mt/auth/drpcauth"
)

// listenAndServePlain serves HTTP and DRPC over the same port using drpcmigrate.
func listenAndServePlain(
	ctx context.Context,
	log *zap.Logger,
	tcpListener net.Listener,
	drpcServer pb.DRPCEdgeAuthServer,
	httpServer *http.Server,
) error {
	listenMux := drpcmigrate.NewListenMux(tcpListener, len(drpcmigrate.DRPCHeader))

	var g errgroup.Group

	drpcListener := listenMux.Route(drpcmigrate.DRPCHeader)
	httpListener := listenMux.Default()

	g.Go(func() error {
		log.Info("Starting DRPC server", zap.String("address", drpcListener.Addr().String()))

		return drpcauth.StartListen(ctx, drpcServer, drpcListener)
	})

	g.Go(func() error {
		log.Info("Starting HTTP server", zap.String("address", httpListener.Addr().String()))

		err := httpServer.Serve(httpListener)
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	})

	g.Go(func() error {
		return listenMux.Run(ctx)
	})

	return g.Wait()
}
