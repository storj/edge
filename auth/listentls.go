// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package auth

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"storj.io/common/pb"
	"storj.io/drpc/drpcmigrate"
	"storj.io/gateway-mt/auth/drpcauth"
)

// serve HTTPS and DRPC+TLS over the same port using drpcmigrate.
func listenAndServe(
	ctx context.Context,
	log *zap.Logger,
	tcpListener net.Listener,
	tlsConfig *tls.Config,
	drpcServer pb.DRPCGatewayAuthServer,
	handler http.Handler,
) error {
	if tlsConfig == nil {
		log.Error("not starting DRPC and HTTPS because of missing TLS configuration")
		return nil
	}

	listenMux := drpcmigrate.NewListenMux(tcpListener, len(drpcmigrate.DRPCHeader))

	httpServer := &http.Server{
		Handler: handler,
	}

	var g errgroup.Group

	g.Go(func() error {
		return listenMux.Run(ctx)
	})

	g.Go(func() error {
		log.Info("Starting HTTPS server")
		listener := tls.NewListener(listenMux.Default(), tlsConfig)

		log.Info("listening for incoming HTTPS connections", zap.String("address", listener.Addr().String()))

		err := httpServer.Serve(listener)
		if errors.Is(err, context.Canceled) || errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		return err
	})

	g.Go(func() error {
		log.Info("Starting DRPC TLS server")
		listener := tls.NewListener(listenMux.Route(drpcmigrate.DRPCHeader), tlsConfig)
		log.Info("listening for incoming DRPC TLS connections", zap.String("address", listener.Addr().String()))

		return drpcauth.StartListen(ctx, drpcServer, listener)
	})

	g.Go(func() error {
		<-ctx.Done()
		return httpServer.Close()
	})

	return g.Wait()
}
