// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package auth

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sync/errgroup"
	"gopkg.in/webhelp.v1/whmon"
	"gopkg.in/webhelp.v1/whroute"

	"storj.io/common/http/requestid"
	"storj.io/common/memory"
	"storj.io/common/pb"
	"storj.io/common/process/gcloudlogging"
	"storj.io/common/sync2"
	"storj.io/edge/pkg/auth/authdb"
	"storj.io/edge/pkg/auth/badgerauth"
	"storj.io/edge/pkg/auth/drpcauth"
	"storj.io/edge/pkg/auth/httpauth"
	"storj.io/edge/pkg/auth/spannerauth"
	"storj.io/edge/pkg/httplog"
	"storj.io/edge/pkg/nodelist"
	"storj.io/edge/pkg/trustedip"
)

var mon = monkit.Package()

const serverShutdownTimeout = 10 * time.Second

// Config holds authservice's configuration.
type Config struct {
	Endpoint          string        `help:"Gateway endpoint URL to return to clients" default:""`
	AuthToken         []string      `help:"auth security token(s) to validate requests" releaseDefault:"" devDefault:""`
	POSTSizeLimit     memory.Size   `help:"maximum size that the incoming POST request body with access grant can be" default:"4KiB"`
	AllowedSatellites []string      `help:"list of satellite NodeURLs allowed for incoming access grants" default:"https://www.storj.io/dcs-satellites"`
	CacheExpiration   time.Duration `help:"length of time satellite addresses are cached for" default:"10m"`
	ShutdownDelay     time.Duration `help:"time to delay server shutdown while returning 503s on the health endpoint" devDefault:"1s" releaseDefault:"45s"`
	IdleTimeout       time.Duration `help:"timeout for idle connections" default:"60s"`

	KVBackend string `help:"key/value store backend url" default:""`
	Migration bool   `help:"create or update the database schema, and then continue service startup" default:"false"`

	ListenAddr    string `user:"true" help:"public HTTP address to listen on" default:":20000"`
	ListenAddrTLS string `user:"true" help:"public HTTPS address to listen on" default:":20001"`

	DRPCListenAddr    string `user:"true" help:"public DRPC address to listen on" default:":20002"`
	DRPCListenAddrTLS string `user:"true" help:"public DRPC+TLS address to listen on" default:":20003"`

	ProxyAddrTLS string `help:"TLS address to listen on for PROXY protocol requests" default:":20005"`

	CertFile                string   `user:"true" help:"server certificate file" default:""`
	KeyFile                 string   `user:"true" help:"server key file" default:""`
	PublicURL               []string `user:"true" help:"comma separated list of public urls for the server TLS certificates (e.g. https://auth.example.com,https://auth.us1.example.com)"`
	RetrievePublicProjectID bool     `user:"true" help:"retrieve and store public project ID when registering access grant" default:"true"`

	CertMagic certMagic

	Node    badgerauth.Config
	Spanner spannerauth.Config
}

// certMagic is a config struct for configuring CertMagic options.
type certMagic struct {
	Enabled bool   `user:"true" help:"use CertMagic to handle TLS certificates" default:"false"`
	KeyFile string `user:"true" help:"path to the service account key file"`
	Email   string `user:"true" help:"email address to use when creating an ACME account"`
	Staging bool   `user:"true" help:"use staging CA endpoints" devDefault:"true" releaseDefault:"false"`
	Bucket  string `user:"true" help:"bucket to use for certificate storage with optional prefix (bucket/prefix)"`
}

// Peer is the representation of authservice.
type Peer struct {
	log     *zap.Logger
	storage authdb.Storage
	adb     *authdb.Database
	res     *httpauth.Resources

	handler       http.Handler
	httpListener  net.Listener
	httpsListener net.Listener

	drpcServer      pb.DRPCEdgeAuthServer
	drpcListener    net.Listener
	drpcTLSListener net.Listener

	proxyTLSListener net.Listener

	config         Config
	areSatsDynamic bool
	endpoint       *url.URL
	tlsConfig      *tls.Config

	satelliteListReload *sync2.Cycle
}

// New constructs new Peer.
//
// TODO(artur): New and constructors, in general, shouldn't take context.Context
// as a parameter.
func New(ctx context.Context, log *zap.Logger, config Config, configDir string) (*Peer, error) {
	if len(config.AllowedSatellites) == 0 {
		return nil, errs.New("allowed satellites parameter '--allowed-satellites' is required")
	}
	allowedSats, areSatsDynamic, err := nodelist.Resolve(ctx, config.AllowedSatellites)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	if len(allowedSats) == 0 {
		return nil, errs.New("allowed satellites parameter '--allowed-satellites' resolved to zero satellites")
	}

	for satelliteID := range allowedSats {
		log.Debug("allowed satellite: " + satelliteID.String())
	}

	if config.Endpoint == "" {
		return nil, errs.New("endpoint parameter '--endpoint' is required")
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	if endpoint.Scheme != "http" && endpoint.Scheme != "https" {
		return nil, errs.New("unexpected scheme found in endpoint parameter %s", endpoint.Scheme)
	}

	var publicURLs []string
	for _, publicURL := range config.PublicURL {
		u, err := url.Parse(publicURL)
		if err != nil {
			return nil, errs.Wrap(err)
		}
		if u.Hostname() == "" {
			return nil, errs.New("unable to parse host from %s", publicURL)
		}
		publicURLs = append(publicURLs, u.Hostname())
	}

	storage, err := OpenStorage(ctx, log.Named("db"), config)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	adb := authdb.NewDatabase(log.Named("authdb"), storage, allowedSats, config.RetrievePublicProjectID)
	res := httpauth.New(log.Named("resources"), adb, endpoint, config.AuthToken, config.POSTSizeLimit)

	tlsInfo := &TLSInfo{
		CertFile:         config.CertFile,
		KeyFile:          config.KeyFile,
		PublicURL:        publicURLs,
		ConfigDir:        configDir,
		ListenAddr:       config.ListenAddrTLS,
		CertMagic:        config.CertMagic.Enabled,
		CertMagicKeyFile: config.CertMagic.KeyFile,
		CertMagicEmail:   config.CertMagic.Email,
		CertMagicStaging: config.CertMagic.Staging,
		CertMagicBucket:  config.CertMagic.Bucket,
	}

	tlsConfig, handler, err := configureTLS(ctx, log, tlsInfo, res)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	// logging. do not log paths - paths have access keys in them.
	handler = requestid.AddToContext(LogResponses(log, LogRequests(log, handler)))

	drpcServer := drpcauth.NewServer(log, adb, endpoint, config.POSTSizeLimit)

	httpListener, err := net.Listen("tcp", config.ListenAddr)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	drpcListener, err := net.Listen("tcp", config.DRPCListenAddr)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	var httpsListener, drpcTLSListener, proxyTLSListener net.Listener
	if tlsConfig != nil {
		httpsListener, err = tls.Listen("tcp", config.ListenAddrTLS, tlsConfig)
		if err != nil {
			return nil, errs.Wrap(err)
		}
		drpcTLSListener, err = tls.Listen("tcp", config.DRPCListenAddrTLS, tlsConfig)
		if err != nil {
			return nil, errs.Wrap(err)
		}

		if config.ProxyAddrTLS != "" {
			proxyListener, err := net.Listen("tcp", config.ProxyAddrTLS)
			if err != nil {
				return nil, errs.Wrap(err)
			}

			proxyTLSListener = tls.NewListener(&proxyproto.Listener{
				Listener: proxyListener,
				Policy: func(upstream net.Addr) (proxyproto.Policy, error) {
					return proxyproto.REQUIRE, nil
				},
			}, tlsConfig)
		}
	}

	return &Peer{
		log:     log,
		storage: storage,
		adb:     adb,
		res:     res,

		handler:       handler,
		httpListener:  httpListener,
		httpsListener: httpsListener,

		drpcServer:      drpcServer,
		drpcListener:    drpcListener,
		drpcTLSListener: drpcTLSListener,

		proxyTLSListener: proxyTLSListener,

		config:         config,
		areSatsDynamic: areSatsDynamic,
		endpoint:       endpoint,
		tlsConfig:      tlsConfig,

		satelliteListReload: sync2.NewCycle(config.CacheExpiration),
	}, nil
}

// LogRequests logs requests.
func LogRequests(log *zap.Logger, h http.Handler) http.Handler {
	return whroute.HandlerFunc(h, func(w http.ResponseWriter, r *http.Request) {
		ce := log.Check(zap.DebugLevel, "request")
		if ce == nil {
			h.ServeHTTP(w, r)
			return
		}

		ce.Write([]zapcore.Field{
			gcloudlogging.LogHTTPRequest(&gcloudlogging.HTTPRequest{
				Protocol:      r.Proto,
				RequestMethod: r.Method,
				RequestSize:   r.ContentLength,
				UserAgent:     r.UserAgent(),
				RemoteIP:      trustedip.GetClientIP(trustedip.NewListTrustAll(), r),
			}),
			zap.String("host", r.Host),
		}...)

		h.ServeHTTP(w, r)
	})
}

// LogResponses logs responses.
func LogResponses(log *zap.Logger, h http.Handler) http.Handler {
	return whmon.MonitorResponse(whroute.HandlerFunc(h,
		func(w http.ResponseWriter, r *http.Request) {
			rw := w.(whmon.ResponseWriter)
			start := time.Now()
			h.ServeHTTP(rw, r)

			if !rw.WroteHeader() {
				rw.WriteHeader(http.StatusOK)
			}

			if ce := log.Check(httplog.StatusLevel(rw.StatusCode()), "response"); ce != nil {
				ce.Write([]zapcore.Field{
					gcloudlogging.LogHTTPRequest(&gcloudlogging.HTTPRequest{
						Protocol:      r.Proto,
						RequestMethod: r.Method,
						RequestSize:   r.ContentLength,
						ResponseSize:  rw.Written(),
						UserAgent:     r.UserAgent(),
						RemoteIP:      trustedip.GetClientIP(trustedip.NewListTrustAll(), r),
						Latency:       time.Since(start),
						Status:        rw.StatusCode(),
					}),
					zap.String("host", r.Host),
					zap.String("request-id", requestid.FromContext(r.Context())),
				}...)
			}
		}))
}

// Run starts authservice. It is also responsible for shutting servers down
// when the context is canceled.
func (p *Peer) Run(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	group, groupCtx := errgroup.WithContext(ctx)

	if p.areSatsDynamic {
		p.satelliteListReload.Start(groupCtx, group, func(ctx context.Context) error {
			reloadSatelliteList(ctx, p.log, p.adb, p.config.AllowedSatellites)
			return nil
		})
		defer p.satelliteListReload.Close()
	}

	group.Go(func() error {
		p.log.Info("Starting HTTP server", zap.String("address", p.httpListener.Addr().String()))
		return p.ServeHTTP(groupCtx, p.httpListener)
	})

	group.Go(func() error {
		return p.ServeDRPC(groupCtx, p.drpcListener)
	})

	if p.tlsConfig == nil {
		p.log.Info("not starting DRPC+TLS and HTTPS because of missing TLS configuration")
	} else {
		group.Go(func() error {
			p.log.Info("Starting HTTPS server", zap.String("address", p.httpsListener.Addr().String()))
			return p.ServeHTTP(groupCtx, p.httpsListener)
		})

		group.Go(func() error {
			p.log.Info("Starting HTTPS (PROXY protocol) server", zap.String("address", p.proxyTLSListener.Addr().String()))
			return p.ServeHTTP(groupCtx, p.proxyTLSListener)
		})

		group.Go(func() error {
			return p.ServeDRPC(groupCtx, p.drpcTLSListener)
		})
	}

	p.res.SetStartupDone()

	return errs.Wrap(group.Wait())
}

// Close closes all authservice's resources. It does not shut down servers that
// started serving in Run(). To do that, the context must be canceled.
// Close will also close any listeners that may still be listening but haven't
// been closed yet. Run() will take care of closing listeners if the context is
// canceled, but closing them here is necessary if Run() was never called.
func (p *Peer) Close() error {
	if p.httpListener != nil {
		_ = p.httpListener.Close()
	}
	if p.httpsListener != nil {
		_ = p.httpListener.Close()
	}
	if p.drpcListener != nil {
		_ = p.drpcListener.Close()
	}
	if p.drpcTLSListener != nil {
		_ = p.drpcTLSListener.Close()
	}
	if p.proxyTLSListener != nil {
		_ = p.proxyTLSListener.Close()
	}

	return errs.Wrap(p.storage.Close())
}

// ServeHTTP starts serving HTTP clients.
func (p *Peer) ServeHTTP(ctx context.Context, listener net.Listener) (err error) {
	server := http.Server{
		IdleTimeout: p.config.IdleTimeout,
		Handler:     p.handler,
	}

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Serve(listener)
	}()

	select {
	case <-ctx.Done():
		p.res.SetShutdown()
		if p.config.ShutdownDelay > 0 {
			p.log.Info("Waiting before server shutdown:", zap.Duration("Delay", p.config.ShutdownDelay))
			time.Sleep(p.config.ShutdownDelay)
		}

		ctx, cancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
		defer cancel()

		err = errs.Combine(server.Shutdown(ctx), server.Close(), ctx.Err())
	case err = <-serverErr:
	}

	if errs.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// ServeDRPC starts serving DRPC clients.
func (p *Peer) ServeDRPC(ctx context.Context, listener net.Listener) error {
	p.log.Info("Starting DRPC server", zap.String("address", listener.Addr().String()))

	return drpcauth.StartListen(ctx, p.drpcServer, p.config.POSTSizeLimit, listener)
}

// Address returns the address of the HTTP listener.
func (p *Peer) Address() string {
	return p.httpListener.Addr().String()
}

// AddressTLS returns the address of the HTTPS listener.
func (p *Peer) AddressTLS() string {
	return p.httpsListener.Addr().String()
}

// DRPCAddress returns the address of the DRPC listener.
func (p *Peer) DRPCAddress() string {
	return p.drpcListener.Addr().String()
}

// DRPCTLSAddress returns the address of the DRPC+TLS listener.
func (p *Peer) DRPCTLSAddress() string {
	return p.drpcTLSListener.Addr().String()
}

// ProxyAddressTLS returns the TLS address for the PROXY protocol listener.
func (p *Peer) ProxyAddressTLS() string {
	return p.proxyTLSListener.Addr().String()
}

func reloadSatelliteList(ctx context.Context, log *zap.Logger, adb *authdb.Database, allowedSatellites []string) {
	log.Debug("Reloading allowed satellite list")
	allowedSatelliteURLs, _, err := nodelist.Resolve(ctx, allowedSatellites)
	if err != nil {
		log.Warn("Error reloading allowed satellite list", zap.Error(err))
	} else {
		adb.SetAllowedSatellites(allowedSatelliteURLs)
	}
}
