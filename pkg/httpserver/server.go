// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package httpserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/googleclouddns"
	"github.com/mholt/acmez"
	"github.com/pires/go-proxyproto"
	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"golang.org/x/net/http2"
	"golang.org/x/sync/errgroup"

	"storj.io/edge/pkg/certstorage"
	"storj.io/edge/pkg/gpublicca"
	"storj.io/edge/pkg/startupcheck"
	"storj.io/edge/pkg/tierquery"
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

	// ProxyAddressTLS is the address to which the https server that handles PROXY protocol requests is bound.
	// It is optional and is not used if TLS is not configured.
	ProxyAddressTLS string

	// Whether requests and responses are logged or not. Sometimes you might provide your own logging middleware instead.
	TrafficLogging bool

	// TLSConfig is the TLS configuration for the server. It is optional.
	TLSConfig *TLSConfig

	// Whether HTTP/2 support should be disabled.
	DisableHTTP2 bool

	// ShutdownTimeout controls how long to wait for requests to finish before
	// returning from Run() after the context is canceled. It defaults to
	// 10 seconds if unset. If set to a negative value, the server will be
	// closed immediately.
	ShutdownTimeout time.Duration

	// IdleTimeout is the maximum amount of time to wait for the
	// next request when keep-alives are enabled.
	IdleTimeout time.Duration

	// StartupCheckConfig configures a startup check that must pass in order for
	// servers to start listening.
	StartupCheckConfig StartupCheckConfig
}

// TestIssuerConfig is configuration to a test ACME server, which if defined will
// issue certs from that instead of any other issuers.
type TestIssuerConfig struct {
	// CA is the address to the test ACME issuer.
	CA string

	// CertificatePath is a filesystem path to the CA issuer certificate.
	CertificatePath string

	// Resolver is an address to a preferred DNS resolver. If not given, it
	// defaults to the system resolver.
	Resolver string
}

// TLSConfig is a struct to handle the preferred/configured TLS options.
type TLSConfig struct {
	// CertMagic obtains and renews TLS certificates and staples OCSP responses
	// Setting this to true will mean the server obtains certificate through Certmagic
	// and no other config such as CertDir, or CertFile will be considered.
	CertMagic bool

	// CertMagicKeyFile is a path to a file containing the CertMagic service account key.
	CertMagicKeyFile string

	// CertMagicDNSChallengeWithGCloudDNS is whether to disable HTTP and TLS
	// ALPN challenges and perform the DNS challenge with Google Cloud DNS (no
	// other providers are supported at the moment).
	CertMagicDNSChallengeWithGCloudDNS bool

	// CertMagicDNSChallengeWithGCloudDNSProject is the project where the Google
	// Cloud DNS zone exists.
	CertMagicDNSChallengeWithGCloudDNSProject string

	// Domain to set the TXT record on, to delegate the challenge to a different
	// domain.
	CertMagicDNSChallengeOverrideDomain string

	// CertMagicEmail is the email address to use when creating an ACME account
	CertMagicEmail string

	// CertMagicTestIssuer is optional configuration to set a testing ACME issuer.
	// If configured, this will be the only issuer used.
	CertMagicTestIssuer *TestIssuerConfig

	// CertMagicStaging use staging CA endpoints
	CertMagicStaging bool

	// CertMagicBucket bucket to use for certstorage
	CertMagicBucket string

	// TierService is the configuration for the tier-querying service.
	TierService tierquery.Config

	// SkipPaidTierAllowlist is a list of domain names to which bypass paid tier queries.
	// If any one value is set to "*" then the paid tier checking is disabled entirely.
	SkipPaidTierAllowlist []string

	// CertMagicPublicURLs is a list of URLs to always issue certificates for.
	//
	// Typically, these are URLs that the service will be mainly reached
	// through, like link.storjshare.io or *.gateway.storjshare.io, etc.
	CertMagicPublicURLs []string

	// CertMagicAsyncPublicURLs is a list of URLs to always issue certificates for.
	//
	// the same as CertMagicPublicURLS, except that ACME operations are performed
	// asynchronously (in the background) and cert errors are not fatal.
	CertMagicAsyncPublicURLs []string

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

	// Ctx context for the oauth2 package which gcslock and gcsops use.
	// oauth2 stores the context passed into its constructors.
	Ctx context.Context
}

// StartupCheckConfig provides startup check configuration.
type StartupCheckConfig struct {
	Enabled    bool
	Satellites []string
	Timeout    time.Duration
}

// Server is the HTTP server.
//
// architecture: Endpoint
type Server struct {
	log  *zap.Logger
	name string

	listener         net.Listener
	listenerTLS      net.Listener
	proxyListenerTLS *proxyproto.Listener
	server           *http.Server
	serverTLS        *http.Server
	proxyServerTLS   *http.Server
	shutdownTimeout  time.Duration
	startupCheck     *startupcheck.NodeURLCheck
}

// CertMagicOnDemandDecisionFunc is a concrete type for
// OnDemandConfig.DecisionFunc in the certmagic package.
type CertMagicOnDemandDecisionFunc func(ctx context.Context, name string) error

// New creates a new URL Service Server.
func New(log *zap.Logger, handler http.Handler, decisionFunc CertMagicOnDemandDecisionFunc, config Config) (*Server, error) {
	switch {
	case config.Address == "":
		return nil, errs.New("server address is required")
	case handler == nil:
		return nil, errs.New("server handler is required")
	}

	tlsConfig, err := configureTLS(log, decisionFunc, config)
	if err != nil {
		return nil, err
	}

	listener, err := net.Listen("tcp", config.Address)
	if err != nil {
		return nil, errs.New("unable to listen on %s: %v", config.Address, err)
	}

	var (
		listenerTLS      net.Listener
		proxyListenerTLS *proxyproto.Listener
	)
	if tlsConfig != nil {
		listenerTLS, err = net.Listen("tcp", config.AddressTLS)
		if err != nil {
			return nil, errs.New("unable to listen on %s: %v", config.AddressTLS, err)
		}

		if config.ProxyAddressTLS != "" {
			proxyListener, err := net.Listen("tcp", config.ProxyAddressTLS)
			if err != nil {
				return nil, errs.New("unable to listen on %s: %v", config.ProxyAddressTLS, err)
			}

			proxyListenerTLS = &proxyproto.Listener{
				Listener: proxyListener,
				Policy: func(upstream net.Addr) (proxyproto.Policy, error) {
					return proxyproto.REQUIRE, nil
				},
			}
		}
	}

	// logging
	if config.TrafficLogging {
		handler = logResponses(log, logRequests(log, handler))
	}

	var nextProto map[string]func(*http.Server, *tls.Conn, http.Handler)
	if config.DisableHTTP2 {
		nextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	}

	server := &http.Server{
		IdleTimeout: config.IdleTimeout,
		Handler:     handler,
		ErrorLog:    zap.NewStdLog(log),
	}

	serverTLS := &http.Server{
		IdleTimeout:  config.IdleTimeout,
		Handler:      handler,
		TLSConfig:    tlsConfig,
		ErrorLog:     zap.NewStdLog(log),
		TLSNextProto: nextProto,
	}

	proxyServerTLS := &http.Server{
		IdleTimeout:  config.IdleTimeout,
		Handler:      handler,
		TLSConfig:    tlsConfig.Clone(),
		ErrorLog:     zap.NewStdLog(log),
		TLSNextProto: nextProto,
	}

	if config.ShutdownTimeout == 0 {
		config.ShutdownTimeout = DefaultShutdownTimeout
	}

	var startupCheck *startupcheck.NodeURLCheck
	if config.StartupCheckConfig.Enabled {
		startupCheck, err = startupcheck.NewNodeURLCheck(startupcheck.NodeURLCheckConfig{
			NodeURLs: config.StartupCheckConfig.Satellites,
			Logger:   log.Sugar(),
			Timeout:  config.StartupCheckConfig.Timeout,
		})
		if err != nil {
			return nil, err
		}
	}

	if config.Name != "" {
		log = log.With(zap.String("server", config.Name))
	}

	return &Server{
		log:              log,
		name:             config.Name,
		listener:         listener,
		listenerTLS:      listenerTLS,
		proxyListenerTLS: proxyListenerTLS,
		server:           server,
		serverTLS:        serverTLS,
		proxyServerTLS:   proxyServerTLS,
		shutdownTimeout:  config.ShutdownTimeout,
		startupCheck:     startupCheck,
	}, nil
}

// Run runs the server.
func (server *Server) Run(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	if server.startupCheck != nil {
		if err = server.startupCheck.Check(ctx); err != nil {
			return err
		}
	}

	var group errgroup.Group

	startServer := func(httpSrv *http.Server, listener net.Listener, name string, useTLS bool) (err error) {
		server.log.With(zap.String("addr", listener.Addr().String())).Sugar().Infof("%s server started", name)
		if useTLS {
			err = httpSrv.ServeTLS(listener, "", "")
		} else {
			err = httpSrv.Serve(listener)
		}
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		server.log.With(zap.Error(err)).Sugar().Errorf("%s server closed unexpectedly", name)
		return err
	}

	group.Go(func() error {
		return startServer(server.server, server.listener, "HTTP", false)
	})
	if server.serverTLS.TLSConfig != nil {
		group.Go(func() error {
			return startServer(server.serverTLS, server.listenerTLS, "HTTPS", true)
		})
	}
	if server.proxyListenerTLS != nil {
		group.Go(func() error {
			return startServer(server.proxyServerTLS, server.proxyListenerTLS, "HTTPS (PROXY protocol)", true)
		})
	}

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

	if server.serverTLS.TLSConfig != nil {
		group.Go(func() error {
			server.log.Info("HTTPS server shutting down")
			return shutdownWithTimeout(server.serverTLS, server.shutdownTimeout)
		})
	}

	if server.proxyListenerTLS != nil {
		group.Go(func() error {
			server.log.Info("HTTPS (PROXY protocol) server shutting down")
			return shutdownWithTimeout(server.proxyServerTLS, server.shutdownTimeout)
		})
	}

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

// ProxyAddrTLS returns the TLS address for PROXY protocol requests.
func (server *Server) ProxyAddrTLS() string {
	return server.proxyListenerTLS.Addr().String()
}

// BaseTLSConfig returns a tls.Config with some good default settings for security.
func (c Config) BaseTLSConfig() *tls.Config {
	var protos []string
	if c.DisableHTTP2 {
		protos = []string{"http/1.1"}
	} else {
		protos = []string{http2.NextProtoTLS, "http/1.1"}
	}
	// these settings give us a score of A on https://www.ssllabs.com/ssltest/index.html
	return &tls.Config{
		NextProtos:             protos,
		MinVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: true, // thanks, jeff hodges! https://groups.google.com/g/golang-nuts/c/m3l0AesTdog/m/8CeLeVVyWw4J
	}
}

func configureTLS(log *zap.Logger, decisionFunc CertMagicOnDemandDecisionFunc, config Config) (*tls.Config, error) {
	if config.TLSConfig == nil {
		return nil, nil
	}

	if config.TLSConfig.CertMagic {
		if config.TLSConfig.CertMagicEmail == "" {
			return nil, errs.New("cert-magic.email must be provided when cert-magic is enabled")
		}
		return configureCertMagic(log, decisionFunc, config)
	}

	tlsConfig := config.BaseTLSConfig()

	if config.TLSConfig.CertDir != "" {
		certs, err := loadCertsFromDir(config.TLSConfig.CertDir)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = certs
		return tlsConfig, nil
	}

	switch {
	case config.TLSConfig.CertFile != "" && config.TLSConfig.KeyFile != "":
	case config.TLSConfig.CertFile == "" && config.TLSConfig.KeyFile == "":
		return nil, nil
	case config.TLSConfig.CertFile != "" && config.TLSConfig.KeyFile == "":
		return nil, errs.New("key file must be provided with cert file")
	case config.TLSConfig.CertFile == "" && config.TLSConfig.KeyFile != "":
		return nil, errs.New("cert file must be provided with key file")
	}

	cert, err := tls.LoadX509KeyPair(config.TLSConfig.CertFile, config.TLSConfig.KeyFile)
	if err != nil {
		return nil, errs.New("unable to load server keypair: %v", err)
	}

	tlsConfig.Certificates = []tls.Certificate{cert}
	return tlsConfig, nil
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

func configureCertMagic(log *zap.Logger, decisionFunc CertMagicOnDemandDecisionFunc, config Config) (*tls.Config, error) {
	// We can't set the logger with the default cache so make our own
	var magic *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			return magic, nil
		},
		// Unlimited cache size
		Capacity: 0,
		Logger:   log,
	})

	jsonKey, err := os.ReadFile(config.TLSConfig.CertMagicKeyFile)
	if err != nil {
		return nil, errs.New("unable to read cert-magic-key-file: %v", err)
	}
	cs, err := certstorage.NewGCS(config.TLSConfig.Ctx, log, jsonKey, config.TLSConfig.CertMagicBucket)
	if err != nil {
		return nil, errs.New("initializing certstorage: %v", err)
	}

	magic = certmagic.New(cache, certmagic.Config{
		OnEvent: func(ctx context.Context, event string, data map[string]any) error {
			switch event {
			case "cert_obtaining", "cert_obtained", "cert_failed":
				var renewal bool
				if r, ok := data["renewal"].(bool); ok {
					renewal = r
				}
				mon.Event("certmagic_"+event, monkit.NewSeriesTag("renewal", strconv.FormatBool(renewal)))
			default:
				mon.Event("certmagic_" + event)
			}
			return nil
		},
		Storage: cs,
		Logger:  log,
	})
	// if decisionFunc is nil, it's better to skip configuring on-demand config
	// as it will delay obtaining certificates for public URLs.
	if decisionFunc != nil {
		magic.OnDemand = &certmagic.OnDemandConfig{DecisionFunc: decisionFunc}
	}

	// Set the AltTLSALPNPort so the solver won't start another listener
	_, port, err := net.SplitHostPort(config.AddressTLS)
	if err != nil {
		return nil, err
	}
	tlsALPNPort, err := net.LookupPort("tcp", port)
	if err != nil {
		return nil, err
	}

	googleCA := gpublicca.New(certmagic.NewACMEIssuer(magic, certmagic.ACMEIssuer{
		CA:                   gpublicca.GooglePublicCAProduction,
		DisableHTTPChallenge: true,
		AltTLSALPNPort:       tlsALPNPort,
		Logger:               log,
		Email:                config.TLSConfig.CertMagicEmail,
		Agreed:               true,
	}), jsonKey)
	letsEncryptCA := certmagic.NewACMEIssuer(magic, certmagic.ACMEIssuer{
		CA:                   certmagic.LetsEncryptProductionCA,
		DisableHTTPChallenge: true,
		AltTLSALPNPort:       tlsALPNPort,
		Logger:               log,
		Email:                config.TLSConfig.CertMagicEmail,
		Agreed:               true,
	})

	tlsConfig := config.BaseTLSConfig()
	tlsConfig.GetCertificate = magic.GetCertificate

	if config.TLSConfig.CertMagicDNSChallengeWithGCloudDNS {
		// Enabling the DNS challenge disables the other challenges for that
		// certmagic.ACMEIssuer instance.
		s := &certmagic.DNS01Solver{
			DNSProvider: &googleclouddns.Provider{
				Project:            config.TLSConfig.CertMagicDNSChallengeWithGCloudDNSProject,
				ServiceAccountJSON: config.TLSConfig.CertMagicKeyFile,
			},
			OverrideDomain: config.TLSConfig.CertMagicDNSChallengeOverrideDomain,
		}
		googleCA.DNS01Solver, letsEncryptCA.DNS01Solver = s, s
	} else {
		tlsConfig.NextProtos = append(tlsConfig.NextProtos, acmez.ACMETLS1Protocol)
	}

	if config.TLSConfig.CertMagicStaging {
		googleCA.CA = gpublicca.GooglePublicCAStaging
		letsEncryptCA.CA = certmagic.LetsEncryptStagingCA
	}

	// Issuers' priority (issuers are tried in order of priority) for obtaining
	// certificates:
	//  1. Google Certificate Manager Public CA
	//  2. Let's Encrypt
	magic.Issuers = []certmagic.Issuer{googleCA, letsEncryptCA}

	if config.TLSConfig.CertMagicTestIssuer != nil {
		caCert, err := os.ReadFile(config.TLSConfig.CertMagicTestIssuer.CertificatePath)
		if err != nil {
			return nil, err
		}
		trustedRoots := x509.NewCertPool()
		trustedRoots.AppendCertsFromPEM(caCert)

		magic.Issuers = []certmagic.Issuer{certmagic.NewACMEIssuer(magic, certmagic.ACMEIssuer{
			CA:                   config.TLSConfig.CertMagicTestIssuer.CA,
			Resolver:             config.TLSConfig.CertMagicTestIssuer.Resolver,
			TrustedRoots:         trustedRoots,
			DisableHTTPChallenge: true,
			AltTLSALPNPort:       tlsALPNPort,
			Logger:               log,
			Email:                config.TLSConfig.CertMagicEmail,
			Agreed:               true,
		})}
	}

	// TODO(artur): figure out if we want to ManageSync here or somewhere else
	// to use the process's context. certmagic.TLS uses context.Background...
	if err := magic.ManageSync(context.TODO(), config.TLSConfig.CertMagicPublicURLs); err != nil {
		return tlsConfig, err
	}
	if len(config.TLSConfig.CertMagicAsyncPublicURLs) > 0 && len(config.TLSConfig.CertMagicAsyncPublicURLs[0]) > 0 {
		return tlsConfig, magic.ManageAsync(context.TODO(), config.TLSConfig.CertMagicAsyncPublicURLs)
	}
	return tlsConfig, nil
}

func shutdownWithTimeout(server *http.Server, timeout time.Duration) error {
	if timeout < 0 {
		return server.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return server.Shutdown(ctx)
}
