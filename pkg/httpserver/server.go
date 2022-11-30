// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package httpserver

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/sync/errgroup"

	"storj.io/gateway-mt/pkg/middleware"
)

var mon = monkit.Package()

const (
	// DefaultShutdownTimeout is the default ShutdownTimeout (see Config).
	DefaultShutdownTimeout = time.Second * 10
)

// Config holds the HTTP server configuration.
type Config struct {
	// Name is the name of the server. It is only used for logging. It can
	// be empty.
	Name string

	// Address is the address to bind the server to. It must be set.
	Address string

	// AddressTLS is the address to bind the https server to. It must be set, but is not used if TLS is not configured.
	AddressTLS string

	// Whether requests and responses are logged or not. Sometimes you might provide your own logging middleware instead.
	TrafficLogging bool

	// TLSConfig is the TLS configuration for the server. It is optional.
	TLSConfig *TLSConfig

	// ShutdownTimeout controls how long to wait for requests to finish before
	// returning from Run() after the context is canceled. It defaults to
	// 10 seconds if unset. If set to a negative value, the server will be
	// closed immediately.
	ShutdownTimeout time.Duration
}

// TLSConfig is a struct to handle the preferred/configured TLS options.
type TLSConfig struct {
	// LetsEncrypt controls whether certs from Let's Encrypt are obtained or not.
	// Setting this to true will mean the server only obtains a Let's Encrypt
	// certificate, and no other config such as CertDir, or CertFile will be considered.
	LetsEncrypt bool

	// PublicURLs is a list of URLs to issue on a Let's Encrypt cert if enabled.
	PublicURLs []string

	// ConfigDir is a path for storing certificate cache data for Let's Encrypt.
	ConfigDir string

	// CertDir provides a path containing one or more certificates that should
	// be loaded. Certs and key files must have the same filename so they can be
	// paired, e.g. mycert.key, and mycert.crt. This config setting is mutually
	// exclusive from CertFile and KeyFile.
	CertDir string

	// CertFile is a path to a file containing a corresponding cert for KeyFile.
	CertFile string

	// KeyFile is a path to a file containing a corresponding key for CertFile.
	KeyFile string
}

// Server is the HTTP server.
//
// architecture: Endpoint
type Server struct {
	log     *zap.Logger
	handler http.Handler
	name    string

	listener        net.Listener
	listenerTLS     net.Listener
	server          *http.Server
	serverTLS       *http.Server
	shutdownTimeout time.Duration
}

// New creates a new URL Service Server.
func New(log *zap.Logger, handler http.Handler, config Config) (*Server, error) {
	switch {
	case config.Address == "":
		return nil, errs.New("server address is required")
	case handler == nil:
		return nil, errs.New("server handler is required")
	}

	tlsConfig, httpHandler, err := configureTLS(config.TLSConfig, handler)
	if err != nil {
		return nil, err
	}

	listener, err := net.Listen("tcp", config.Address)
	if err != nil {
		return nil, errs.New("unable to listen on %s: %v", config.Address, err)
	}

	var listenerTLS net.Listener
	if tlsConfig != nil {
		listenerTLS, err = net.Listen("tcp", config.AddressTLS)
		if err != nil {
			return nil, errs.New("unable to listen on %s: %v", config.AddressTLS, err)
		}
	}

	// logging
	if config.TrafficLogging {
		httpHandler = middleware.AddRequestID(logResponses(log, logRequests(log, httpHandler)))
		handler = middleware.AddRequestID(logResponses(log, logRequests(log, handler)))
	}

	server := &http.Server{
		Handler:  httpHandler,
		ErrorLog: zap.NewStdLog(log),
	}

	serverTLS := &http.Server{
		Handler:   handler,
		TLSConfig: tlsConfig,
		ErrorLog:  zap.NewStdLog(log),
	}

	if config.ShutdownTimeout == 0 {
		config.ShutdownTimeout = DefaultShutdownTimeout
	}

	if config.Name != "" {
		log = log.With(zap.String("server", config.Name))
	}

	return &Server{
		log:             log,
		name:            config.Name,
		listener:        listener,
		listenerTLS:     listenerTLS,
		server:          server,
		serverTLS:       serverTLS,
		shutdownTimeout: config.ShutdownTimeout,
		handler:         handler,
	}, nil
}

// Run runs the server.
func (server *Server) Run(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	var group errgroup.Group

	group.Go(func() (err error) {
		server.log.With(zap.String("addr", server.Addr())).Sugar().Info("HTTP server started")
		err = server.server.Serve(server.listener)

		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		server.log.With(zap.Error(err)).Error("Server closed unexpectedly")
		return err
	})

	group.Go(func() (err error) {
		if server.serverTLS.TLSConfig != nil {
			server.log.With(zap.String("addr", server.AddrTLS())).Sugar().Info("HTTPS server started")
			err = server.serverTLS.ServeTLS(server.listenerTLS, "", "")

			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			server.log.With(zap.Error(err)).Error("Server closed unexpectedly")
			return err
		}
		return nil
	})

	return group.Wait()
}

// Shutdown gracefully shuts the server down, with a given timeout.
// If timeout is less than 0, all connections are closed immediately instead
// of waiting.
func (server *Server) Shutdown() (err error) {
	var group errgroup.Group

	group.Go(func() error {
		server.log.Info("HTTP server shutting down")
		return shutdownWithTimeout(server.server, server.shutdownTimeout)
	})

	group.Go(func() error {
		if server.serverTLS.TLSConfig != nil {
			server.log.Info("HTTPS server shutting down")
			return shutdownWithTimeout(server.serverTLS, server.shutdownTimeout)
		}
		return nil
	})

	return group.Wait()
}

// Addr returns the public address.
func (server *Server) Addr() string {
	return server.listener.Addr().String()
}

// AddrTLS returns the public TLS address.
func (server *Server) AddrTLS() string {
	return server.listenerTLS.Addr().String()
}

// BaseTLSConfig returns a tls.Config with some good default settings for security.
func BaseTLSConfig() *tls.Config {
	// these settings give us a score of A on https://www.ssllabs.com/ssltest/index.html
	return &tls.Config{
		NextProtos:             []string{"h2", "http/1.1"},
		MinVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: true, // thanks, jeff hodges! https://groups.google.com/g/golang-nuts/c/m3l0AesTdog/m/8CeLeVVyWw4J
	}
}

func configureTLS(config *TLSConfig, handler http.Handler) (*tls.Config, http.Handler, error) {
	if config == nil {
		return nil, handler, nil
	}

	if config.LetsEncrypt {
		return configureLetsEncrypt(config, handler)
	}

	tlsConfig := BaseTLSConfig()

	if config.CertDir != "" {
		certs, err := loadCertsFromDir(config.CertDir)
		if err != nil {
			return nil, nil, err
		}
		tlsConfig.Certificates = certs
		return tlsConfig, handler, nil
	}

	switch {
	case config.CertFile != "" && config.KeyFile != "":
	case config.CertFile == "" && config.KeyFile == "":
		return nil, handler, nil
	case config.CertFile != "" && config.KeyFile == "":
		return nil, nil, errs.New("key file must be provided with cert file")
	case config.CertFile == "" && config.KeyFile != "":
		return nil, nil, errs.New("cert file must be provided with key file")
	}

	cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		return nil, nil, errs.New("unable to load server keypair: %v", err)
	}

	tlsConfig.Certificates = []tls.Certificate{cert}
	return tlsConfig, handler, nil
}

func loadCertsFromDir(configDir string) ([]tls.Certificate, error) {
	certFiles, err := filepath.Glob(filepath.Join(configDir, "*.crt"))
	if err != nil {
		return nil, errs.New("Error reading certificate directory '%s'", certFiles)
	}
	var certificates []tls.Certificate
	for _, crt := range certFiles {
		key := crt[0:len(crt)-4] + ".key"
		_, err := os.Stat(key)
		if err != nil {
			return nil, errs.New("unable to locate key for cert %s (expecting %s): %v", crt, key, err)
		}

		cert, err := tls.LoadX509KeyPair(crt, key)
		if err != nil {
			return nil, errs.New("unable to load server keypair: %v", err)
		}
		certificates = append(certificates, cert)
	}

	return certificates, nil
}

func configureLetsEncrypt(config *TLSConfig, handler http.Handler) (*tls.Config, http.Handler, error) {
	if len(config.PublicURLs) != 1 {
		return nil, nil, errs.New("cannot do self lets encrypt configuration for multiple hostnames")
	}
	parsedURL, err := url.Parse(config.PublicURLs[0])
	if err != nil {
		return nil, nil, err
	}
	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(parsedURL.Host),
		Cache:      autocert.DirCache(filepath.Join(config.ConfigDir, ".certs")),
	}

	tlsConfig := BaseTLSConfig()
	tlsConfig.GetCertificate = certManager.GetCertificate
	return tlsConfig, certManager.HTTPHandler(handler), nil
}

func shutdownWithTimeout(server *http.Server, timeout time.Duration) error {
	if timeout < 0 {
		return server.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return server.Shutdown(ctx)
}
