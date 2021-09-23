// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/gorilla/mux"
	"github.com/minio/minio/cmd/logger"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"storj.io/common/errs2"
	"storj.io/gateway-mt/pkg/minio"
	"storj.io/gateway-mt/pkg/server/middleware"
	"storj.io/gateway-mt/pkg/trustedip"
	"storj.io/private/version"
)

var (
	// Error is an error class for internal Multinode Dashboard http server error.
	Error = errs.Class("gateway")

	minioTargetOnce sync.Once
)

// Server represents an S3 compatible http server.
type Server struct {
	http     http.Server
	listener net.Listener
	log      *zap.Logger
}

// New returns new instance of an S3 compatible http server.
//
// TODO: at the time of wiring the new Signature middleware we'll start to use/
// pass around the trustedIPs parameter.
func New(listener net.Listener, log *zap.Logger, tlsConfig *tls.Config, useSetInMemoryMiddleware bool,
	trustedIPs trustedip.List, insecureLogAll bool, corsAllowedOrigins []string) *Server {
	r := mux.NewRouter()
	r.SkipClean(true)

	s := &Server{listener: listener, log: log, http: http.Server{Handler: r}}

	if tlsConfig != nil {
		s.listener = tls.NewListener(listener, tlsConfig)
		s.http.TLSConfig = tlsConfig
	}

	publicServices := r.PathPrefix("/-/").Subrouter()
	publicServices.HandleFunc("/health", s.healthCheck)
	publicServices.HandleFunc("/version", s.versionInfo)

	if useSetInMemoryMiddleware {
		r.Use(middleware.SetInMemory)
	}

	// Gorilla matches in the order things are defined, so fall back
	// to minio implementations if we haven't handled something
	minio.RegisterHealthCheckRouter(r)
	minio.RegisterMetricsRouter(r)
	minio.RegisterAPIRouter(r)

	// Ensure we log any minio system errors sent by minio logging.
	// Target slice in minio is a global, so additionally ensure only one logger
	// is added, such may be the case if starting multiple servers in parallel.
	minioTargetOnce.Do(func() {
		// error is ignored as we don't use validation of target.
		_ = logger.AddTarget(NewMinioSystemLogTarget(s.log))
	})

	r.Use(middleware.Metrics)
	r.Use(minio.GlobalHandlers...)

	s.http.Handler = minio.CriticalErrorHandler{Handler: minio.CorsHandler(corsAllowedOrigins)(r)}

	// we deliberately don't log paths for this service because they have
	// sensitive information.
	s.http.Handler = LogRequests(s.log, s.http.Handler, insecureLogAll)
	s.http.Handler = LogResponses(s.log, s.http.Handler, insecureLogAll)

	return s
}

func (s *Server) healthCheck(w http.ResponseWriter, r *http.Request) {
	// TODO: should this function do any tests to confirm the server is operational before returning a 200?
	// this function should be low-effort, in the sense that the load balancer is going to be hitting it regularly.
	w.WriteHeader(http.StatusOK)
}

func (s *Server) versionInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, version.Build.Version.String())
}

// Run starts the S3 compatible http server.
func (s *Server) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	var group errgroup.Group
	group.Go(func() error {
		<-ctx.Done()
		return Error.Wrap(s.http.Shutdown(context.Background()))
	})
	group.Go(func() error {
		defer cancel()
		err := s.http.Serve(s.listener)
		if errs2.IsCanceled(err) || errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		return Error.Wrap(err)
	})
	return group.Wait()
}

// Close closes server and underlying listener.
func (s *Server) Close() error {
	return Error.Wrap(s.http.Close())
}
