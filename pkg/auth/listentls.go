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
	"storj.io/gateway-mt/pkg/auth/drpcauth"
)

// listenAndServeTLS serves HTTPS and DRPC+TLS over the same port using drpcmigrate.
func listenAndServeTLS(
	ctx context.Context,
	log *zap.Logger,
	tcpListener net.Listener,
	tlsConfig *tls.Config,
	drpcServer pb.DRPCEdgeAuthServer,
	httpServer *http.Server,
) error {
	if tlsConfig == nil {
		log.Info("not starting DRPC+TLS and HTTPS because of missing TLS configuration")
		return nil
	}

	listenMux := drpcmigrate.NewListenMux(tcpListener, len(drpcmigrate.DRPCHeader))

	var g errgroup.Group

	drpcListener := tls.NewListener(listenMux.Route(drpcmigrate.DRPCHeader), tlsConfig)
	httpListener := tls.NewListener(listenMux.Default(), tlsConfig)

	g.Go(func() error {
		log.Info("Starting DRPC TLS server", zap.String("address", drpcListener.Addr().String()))

		return drpcauth.StartListen(ctx, drpcServer, drpcListener)
	})

	g.Go(func() error {
		log.Info("Starting HTTPS server", zap.String("address", httpListener.Addr().String()))

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
