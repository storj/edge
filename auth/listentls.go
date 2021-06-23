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
)

// serve HTTPS.
func listenAndServe(
	ctx context.Context,
	log *zap.Logger,
	tcpListener net.Listener,
	tlsConfig *tls.Config,
	handler http.Handler,
) error {
	if tlsConfig == nil {
		log.Error("not starting HTTPS because of missing TLS configuration")
		return nil
	}

	httpServer := &http.Server{
		Handler: handler,
	}

	var g errgroup.Group

	g.Go(func() error {
		log.Info("Starting HTTPS server")
		listener := tls.NewListener(tcpListener, tlsConfig)
		log.Info("listening for incoming HTTPS connections", zap.String("address", listener.Addr().String()))

		err := httpServer.Serve(listener)
		if errors.Is(err, context.Canceled) || errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		return err
	})

	g.Go(func() error {
		<-ctx.Done()
		return httpServer.Close()
	})

	return g.Wait()
}
