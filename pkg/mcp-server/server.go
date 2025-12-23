// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package mcpserver

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/errs2"
	"storj.io/common/http/requestid"
	"storj.io/common/rpc/rpcpool"
	"storj.io/common/version"
	"storj.io/edge/pkg/authclient"
	"storj.io/edge/pkg/httpserver"
	"storj.io/edge/pkg/mcp-server/middleware"
	"storj.io/edge/pkg/mcp-server/tools"
)

// Error is a class of mcp-server errors.
var Error = errs.Class("mcp-server")

// Peer represents an MCP server.
type Peer struct {
	log    *zap.Logger
	server *httpserver.Server
	config Config

	inShutdown int32
}

// New returns a new instance of an MCP server.
func New(log *zap.Logger, config Config) (*Peer, error) {
	r := mux.NewRouter()

	mcpServer := server.NewMCPServer(
		"storj-mcp-server",
		version.Build.Version.String(),
		server.WithToolCapabilities(false),
	)

	tools := tools.New(tools.Config{
		LinkSharingURL: config.LinkSharingURL,
		AuthServiceURL: config.Auth.BaseURL,
		SatelliteConnectionPool: rpcpool.Options{
			Name:           "satellite",
			Capacity:       config.SatelliteConnectionPool.Capacity,
			KeyCapacity:    config.SatelliteConnectionPool.KeyCapacity,
			IdleExpiration: config.SatelliteConnectionPool.IdleExpiration,
			MaxLifetime:    config.SatelliteConnectionPool.MaxLifetime,
		},
		ConnectionPool: rpcpool.Options{
			Name:           "default",
			Capacity:       config.ConnectionPool.Capacity,
			KeyCapacity:    config.ConnectionPool.KeyCapacity,
			IdleExpiration: config.ConnectionPool.IdleExpiration,
			MaxLifetime:    config.ConnectionPool.MaxLifetime,
		},
	})
	tools.Add(mcpServer)

	authClient := authclient.New(config.Auth)

	handler := &Handler{
		server:     server.NewStreamableHTTPServer(mcpServer, server.WithStateLess(true)),
		authClient: authClient,
		log:        log,
	}

	r.Use(requestid.AddToContext)

	mcpRegisterRouter := r.PathPrefix("/mcp/register").Subrouter()
	mcpRegisterRouter.Use(middleware.NewLogRequests(log))
	mcpRegisterRouter.Use(middleware.NewLogResponses(log))
	mcpRegisterRouter.HandleFunc("", handler.Register).Methods(http.MethodPost)

	mcpRPCRouter := r.PathPrefix("/mcp/jsonrpc").Subrouter()
	mcpRPCRouter.Use(middleware.CredentialsMiddleware(log, authClient))
	mcpRPCRouter.Use(middleware.EventHandler)
	mcpRPCRouter.Use(middleware.NewLogRequests(log))
	mcpRPCRouter.Use(middleware.NewLogResponses(log))
	mcpRPCRouter.HandleFunc("", handler.RPC)

	var tlsConfig *httpserver.TLSConfig
	if !config.InsecureDisableTLS {
		tlsConfig = &httpserver.TLSConfig{
			CertMagic:                                 config.CertMagic.Enabled,
			CertMagicKeyFile:                          config.CertMagic.KeyFile,
			CertMagicDNSChallengeWithGCloudDNS:        true,
			CertMagicDNSChallengeWithGCloudDNSProject: config.CertMagic.Project,
			CertMagicDNSChallengeOverrideDomain:       config.CertMagic.ChallengeOverrideDomain,
			CertMagicEmail:                            config.CertMagic.Email,
			CertMagicStaging:                          config.CertMagic.Staging,
			CertMagicBucket:                           config.CertMagic.Bucket,
			CertMagicPublicURLs:                       strings.Split(config.DomainName, ","),
		}
	}

	server, err := httpserver.New(log, r, nil, httpserver.Config{
		Address:         config.Address,
		AddressTLS:      config.AddressTLS,
		ProxyAddressTLS: config.ProxyAddressTLS,
		TLSConfig:       tlsConfig,
		IdleTimeout:     config.IdleTimeout,
	})
	if err != nil {
		return nil, err
	}

	peer := Peer{
		log:    log,
		server: server,
		config: config,
	}

	r.HandleFunc("/health", peer.healthCheck)

	return &peer, nil
}

// Run starts the MCP server.
func (s *Peer) Run(ctx context.Context) error {
	var g errs2.Group
	g.Go(func() error {
		return s.server.Run(ctx)
	})
	return errs.Combine(g.Wait()...)
}

// Close shuts down the server and all underlying resources.
func (s *Peer) Close() error {
	atomic.StoreInt32(&s.inShutdown, 1)
	if s.config.ShutdownDelay > 0 {
		s.log.Info("Waiting before server shutdown", zap.Duration("delay", s.config.ShutdownDelay))
		time.Sleep(s.config.ShutdownDelay)
	}

	return s.server.Shutdown()
}

// Address returns the web address the peer is listening on.
func (s *Peer) Address() string {
	return s.server.Addr()
}

// AddressTLS returns the TLS web address the peer is listening on.
func (s *Peer) AddressTLS() string {
	return s.server.AddrTLS()
}

func (s *Peer) healthCheck(w http.ResponseWriter, r *http.Request) {
	if atomic.LoadInt32(&s.inShutdown) != 0 {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}
