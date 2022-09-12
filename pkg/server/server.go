// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"gopkg.in/webhelp.v1/whroute"

	"storj.io/common/eventstat"
	"storj.io/common/rpc/rpcpool"
	"storj.io/gateway-mt/pkg/authclient"
	"storj.io/gateway-mt/pkg/httpserver"
	"storj.io/gateway-mt/pkg/minio"
	"storj.io/gateway-mt/pkg/server/gw"
	"storj.io/gateway-mt/pkg/server/middleware"
	"storj.io/gateway-mt/pkg/trustedip"
	"storj.io/gateway/miniogw"
	"storj.io/private/debug"
	"storj.io/private/version"
	"storj.io/uplink"
	"storj.io/uplink/private/transport"
)

var (
	mon = monkit.Package()

	// Error is an error class S3 Gateway http server error.
	Error = errs.Class("gateway")

	minioOnce sync.Once

	// StatRegistry is a specific registry which is reported only to one destination
	// it is used for event statistics with unbounded cardinality.
	StatRegistry = eventstat.Registry{}
)

// Peer represents an S3 compatible http server.
//
// Note that Peer relies upon Minio global variables, which are protected by a Sync.Once() construct.
// Once Peer.Run() has been called, new instances of a Peer will not update any configuration used
// by Minio.
type Peer struct {
	server     *httpserver.Server
	log        *zap.Logger
	config     Config
	closeLayer func(context.Context) error
}

// New returns new instance of an S3 compatible http server.
func New(config Config, log *zap.Logger, trustedIPs trustedip.List, corsAllowedOrigins []string,
	authClient *authclient.AuthClient, domainNames []string, concurrentAllowed uint) (*Peer, error) {
	r := mux.NewRouter()
	r.SkipClean(true)
	r.UseEncodedPath()

	publicServices := r.PathPrefix("/-/").Subrouter()
	publicServices.HandleFunc("/health", healthCheck)
	publicServices.HandleFunc("/version", versionInfo)

	if config.EncodeInMemory {
		r.Use(middleware.SetInMemory)
	}

	// Create object API handler
	connectionPool := rpcpool.New(rpcpool.Options(config.ConnectionPool))

	uplinkConfig := configureUplinkConfig(config.Client)

	layer, err := gw.NewMultiTenantLayer(miniogw.NewStorjGateway(config.S3Compatibility), connectionPool, uplinkConfig, config.InsecureLogAll)
	if err != nil {
		return nil, err
	}
	minio.RegisterAPIRouter(r, layer, domainNames, concurrentAllowed, corsAllowedOrigins)

	r.Use(middleware.NewMetrics("gmt"))
	r.Use(middleware.AccessKey(authClient, trustedIPs, log))
	r.Use(minio.GlobalHandlers...)

	// we deliberately don't log paths for this service because they have
	// sensitive information. Note that middleware.AccessKey is chained before
	// so we can use encrypted credentials while logging requests/responses.
	r.Use(middleware.NewLogRequests(log, config.InsecureLogAll))
	r.Use(middleware.NewLogResponses(log, config.InsecureLogAll))

	var handler http.Handler
	handler = minio.CriticalErrorHandler{Handler: minio.CorsHandler(corsAllowedOrigins)(r)}

	// map with upper bound / memory limit, sent over UDP.
	agentCounter := StatRegistry.NewTagCounter("s3_http_user_agent", "agent")
	// similar, in-memory counter, but not sent over. Collects events since last /top call.
	topCounter := debug.Top.NewTagCounter("s3_http_user_agent", "agent")

	agentCollector := NewAgentCollector("s3_user_agent", func(name string) {
		agentCounter(name)
		topCounter(name)
	})
	handler = agentCollector.Wrap(handler)

	ipCounter := debug.Top.NewTagCounter("s3_http_ip", "ip")
	handler = wrapWithIPCounter(handler, ipCounter, trustedIPs)

	var tlsConfig *httpserver.TLSConfig
	if !config.InsecureDisableTLS {
		tlsConfig = &httpserver.TLSConfig{
			CertDir: config.CertDir,
		}
	}

	server, err := httpserver.New(log, handler, httpserver.Config{
		Address:        config.Server.Address,
		AddressTLS:     config.Server.AddressTLS,
		TLSConfig:      tlsConfig,
		TrafficLogging: false, // gateway-mt has its own logging middleware for this
	})
	if err != nil {
		return nil, err
	}

	return &Peer{
		log:        log,
		server:     server,
		config:     config,
		closeLayer: layer.Shutdown,
	}, nil
}

func wrapWithIPCounter(handler http.Handler, counter eventstat.Sink, trustedIPs trustedip.List) http.Handler {
	return whroute.HandlerFunc(handler, func(writer http.ResponseWriter, request *http.Request) {
		counter(trustedip.GetClientIP(trustedIPs, request))
		handler.ServeHTTP(writer, request)
	})
}

// configureUplinkConfig configures new uplink.Config using clientConfig.
func configureUplinkConfig(clientConfig ClientConfig) uplink.Config {
	ret := uplink.Config{
		DialTimeout: clientConfig.DialTimeout,
	}

	if !clientConfig.UseQosAndCC {
		// An unset DialContext defaults to BackgroundDialer's CC and QOS
		// settings.
		ret.DialContext = (&net.Dialer{}).DialContext
	}

	transport.SetMaximumBufferSize(&ret, clientConfig.MaximumBufferSize.Int())

	return ret
}

func healthCheck(w http.ResponseWriter, r *http.Request) {
	// TODO: should this function do any tests to confirm the server is operational before returning a 200?
	// this function should be low-effort, in the sense that the load balancer is going to be hitting it regularly.
	w.WriteHeader(http.StatusOK)
}

func versionInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, version.Build.Version.String())
}

// Run starts the S3 compatible http server.
func (s *Peer) Run(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	// Minio, Gateway, and the LogTarget are global, so additionally ensure only one
	// of each are added, such may be the case if starting multiple servers in parallel.
	minioOnce.Do(func() {
		minio.StartMinio(!s.config.InsecureDisableTLS)
	})

	return s.server.Run(ctx)
}

// Close shuts down the server and all underlying resources.
func (s *Peer) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// note: httpserver.Shutdown has its own configured timeout
	return Error.Wrap(errs.Combine(s.closeLayer(ctx), s.server.Shutdown()))
}

// Address returns the web address the peer is listening on.
func (s *Peer) Address() string {
	return s.server.Addr()
}

// AddressTLS returns the TLS web address the peer is listening on.
func (s *Peer) AddressTLS() string {
	return s.server.AddrTLS()
}
