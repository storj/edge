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
	"time"

	"github.com/gorilla/mux"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/rpc/rpcpool"
	"storj.io/gateway-mt/pkg/authclient"
	"storj.io/gateway-mt/pkg/minio"
	"storj.io/gateway-mt/pkg/server/middleware"
	"storj.io/gateway-mt/pkg/trustedip"
	"storj.io/gateway/miniogw"
	"storj.io/minio/cmd"
	"storj.io/minio/cmd/logger"
	"storj.io/minio/pkg/auth"
	"storj.io/private/version"
	"storj.io/uplink"
)

var (
	// Error is an error class for internal Multinode Dashboard http server error.
	Error = errs.Class("gateway")

	minioOnce sync.Once
)

// Peer represents an S3 compatible http server.
//
// Note that Peer relies upon Minio global variables, which are protected by a Sync.Once() construct.
// Once Peer.Run() has been called, new instances of a Peer will not update any configuration used
// by Minio.
type Peer struct {
	http     http.Server
	listener net.Listener
	log      *zap.Logger
	config   Config
}

// New returns new instance of an S3 compatible http server.
func New(config Config, log *zap.Logger, tlsConfig *tls.Config, trustedIPs trustedip.List, corsAllowedOrigins []string, authClient *authclient.AuthClient) (*Peer, error) {
	r := mux.NewRouter()
	r.SkipClean(true)
	r.UseEncodedPath()

	listener, err := net.Listen("tcp", config.Server.Address)
	if err != nil {
		return nil, err
	}
	s := &Peer{listener: listener, log: log, http: http.Server{Handler: r}, config: config}

	if tlsConfig != nil {
		s.listener = tls.NewListener(listener, tlsConfig)
		s.http.TLSConfig = tlsConfig
	}

	publicServices := r.PathPrefix("/-/").Subrouter()
	publicServices.HandleFunc("/health", s.healthCheck)
	publicServices.HandleFunc("/version", s.versionInfo)

	if config.EncodeInMemory {
		r.Use(middleware.SetInMemory)
	}

	// Gorilla matches in the order things are defined, so fall back
	// to minio implementations if we haven't handled something
	minio.RegisterHealthCheckRouter(r)
	minio.RegisterMetricsRouter(r)
	minio.RegisterAPIRouter(r)

	r.Use(middleware.Metrics)
	r.Use(middleware.AccessKey(authClient, trustedIPs))
	r.Use(minio.GlobalHandlers...)

	s.http.Handler = minio.CriticalErrorHandler{Handler: minio.CorsHandler(corsAllowedOrigins)(r)}

	// we deliberately don't log paths for this service because they have
	// sensitive information.
	s.http.Handler = LogRequests(s.log, s.http.Handler, config.InsecureLogAll)
	s.http.Handler = LogResponses(s.log, s.http.Handler, config.InsecureLogAll)

	return s, nil
}

func (s *Peer) healthCheck(w http.ResponseWriter, r *http.Request) {
	// TODO: should this function do any tests to confirm the server is operational before returning a 200?
	// this function should be low-effort, in the sense that the load balancer is going to be hitting it regularly.
	w.WriteHeader(http.StatusOK)
}

func (s *Peer) versionInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, version.Build.Version.String())
}

// Run starts the S3 compatible http server.
func (s *Peer) Run() error {
	// Minio, Gateway, and the LogTarget are global, so additionally ensure only one
	// of each are added, such may be the case if starting multiple servers in parallel.
	var err error
	minioOnce.Do(func() {
		// Create object API handler and start Minio
		uplinkConfig := uplink.Config{}
		uplinkConfig.DialTimeout = s.config.Client.DialTimeout
		if !s.config.Client.UseQosAndCC {
			// an unset DialContext defaults to BackgroundDialer's CC and QOS settings
			uplinkConfig.DialContext = (&net.Dialer{}).DialContext
		}
		connectionPool := rpcpool.New(rpcpool.Options(s.config.ConnectionPool))
		gmt := NewMultiTenantGateway(miniogw.NewStorjGateway(s.config.S3Compatibility), connectionPool, uplinkConfig, s.config.InsecureLogAll)
		var gatewayLayer cmd.ObjectLayer
		gatewayLayer, err = gmt.NewGatewayLayer(auth.Credentials{})
		minio.StartMinio(&minio.IAMAuthStore{}, gatewayLayer)
		// Ensure we log any minio system errors sent by minio logging.
		// Error is ignored as we don't use validation of target.
		_ = logger.AddTarget(NewMinioSystemLogTarget(s.log))
	})
	if err != nil {
		return err
	}

	if err = s.http.Serve(s.listener); !errors.Is(err, http.ErrServerClosed) {
		return Error.Wrap(err)
	}

	return nil
}

// Close closes server and underlying listener.
func (s *Peer) Close() error {
	ctx, canc := context.WithTimeout(context.Background(), 10*time.Second)
	defer canc()

	return Error.Wrap(s.http.Shutdown(ctx))
}

// Address returns the web address the peer is listening on.
func (s *Peer) Address() string {
	return s.listener.Addr().String()
}
