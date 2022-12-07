// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package auth

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"sort"
	"time"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sync/errgroup"
	"gopkg.in/webhelp.v1/whmon"
	"gopkg.in/webhelp.v1/whroute"

	"storj.io/common/memory"
	"storj.io/common/pb"
	"storj.io/common/sync2"
	"storj.io/gateway-mt/pkg/auth/authdb"
	"storj.io/gateway-mt/pkg/auth/badgerauth"
	"storj.io/gateway-mt/pkg/auth/badgerauth/badgerauthmigration"
	"storj.io/gateway-mt/pkg/auth/drpcauth"
	"storj.io/gateway-mt/pkg/auth/httpauth"
	"storj.io/gateway-mt/pkg/auth/satellitelist"
	"storj.io/gateway-mt/pkg/middleware"
	"storj.io/gateway-mt/pkg/trustedip"
)

var mon = monkit.Package()

const serverShutdownTimeout = 10 * time.Second

// Config holds authservice's configuration.
type Config struct {
	Endpoint          string        `help:"Gateway endpoint URL to return to clients" default:""`
	AuthToken         string        `help:"auth security token to validate requests" releaseDefault:"" devDefault:""`
	POSTSizeLimit     memory.Size   `help:"maximum size that the incoming POST request body with access grant can be" default:"4KiB"`
	AllowedSatellites []string      `help:"list of satellite NodeURLs allowed for incoming access grants" default:"https://www.storj.io/dcs-satellites"`
	CacheExpiration   time.Duration `help:"length of time satellite addresses are cached for" default:"10m"`

	KVBackend string `help:"key/value store backend url" default:""`
	Migration bool   `help:"create or update the database schema, and then continue service startup" default:"false"`

	ListenAddr    string `user:"true" help:"public HTTP address to listen on" default:":20000"`
	ListenAddrTLS string `user:"true" help:"public HTTPS address to listen on" default:":20001"`

	DRPCListenAddr    string `user:"true" help:"public DRPC address to listen on" default:":20002"`
	DRPCListenAddrTLS string `user:"true" help:"public DRPC+TLS address to listen on" default:":20003"`

	LetsEncrypt bool   `user:"true" help:"use lets-encrypt to handle TLS certificates" default:"false"`
	CertFile    string `user:"true" help:"server certificate file" default:""`
	KeyFile     string `user:"true" help:"server key file" default:""`
	PublicURL   string `user:"true" help:"public url for the server, for the TLS certificate" devDefault:"http://localhost:20000" releaseDefault:""`

	DeleteUnused DeleteUnusedConfig

	Node          badgerauth.Config
	NodeMigration badgerauthmigration.Config
}

// DeleteUnusedConfig is a config struct for configuring unused records deletion
// chores.
type DeleteUnusedConfig struct {
	Run                bool          `help:"whether to run unused records deletion chore" default:"false"`
	Interval           time.Duration `help:"interval unused records deletion chore waits to start next iteration" default:"24h"`
	AsOfSystemInterval time.Duration `help:"the interval specified in AS OF SYSTEM in unused records deletion chore query as negative interval" default:"5s"`
	SelectSize         int           `help:"batch size of records selected for deletion at a time" default:"10000"`
	DeleteSize         int           `help:"batch size of records to delete from selected records at a time" default:"1000"`
}

// Peer is the representation of authservice.
type Peer struct {
	log *zap.Logger
	kv  authdb.KV
	adb *authdb.Database
	res *httpauth.Resources

	handler       http.Handler
	httpListener  net.Listener
	httpsListener net.Listener

	drpcServer      pb.DRPCEdgeAuthServer
	drpcListener    net.Listener
	drpcTLSListener net.Listener

	config         Config
	areSatsDynamic bool
	endpoint       *url.URL
	tlsConfig      *tls.Config

	satelliteListReload   *sync2.Cycle
	unusedRecordsDeletion *sync2.Cycle
}

// New constructs new Peer.
//
// TODO(artur): New and constructors, in general, shouldn't take context.Context
// as a parameter.
func New(ctx context.Context, log *zap.Logger, config Config, configDir string) (*Peer, error) {
	if len(config.AllowedSatellites) == 0 {
		return nil, errs.New("allowed satellites parameter '--allowed-satellites' is required")
	}
	allowedSats, areSatsDynamic, err := satellitelist.LoadSatelliteURLs(ctx, config.AllowedSatellites)
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

	kv, err := OpenKV(ctx, log.Named("db"), config)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	adb := authdb.NewDatabase(kv, allowedSats)
	res := httpauth.New(log.Named("resources"), adb, endpoint, config.AuthToken, config.POSTSizeLimit)

	tlsInfo := &TLSInfo{
		LetsEncrypt: config.LetsEncrypt,
		CertFile:    config.CertFile,
		KeyFile:     config.KeyFile,
		PublicURL:   config.PublicURL,
		ConfigDir:   configDir,
	}

	tlsConfig, handler, err := configureTLS(tlsInfo, res)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	// logging. do not log paths - paths have access keys in them.
	handler = middleware.AddRequestID(LogResponses(log, LogRequests(log, handler)))

	drpcServer := drpcauth.NewServer(log, adb, endpoint, config.POSTSizeLimit)

	httpListener, err := net.Listen("tcp", config.ListenAddr)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	drpcListener, err := net.Listen("tcp", config.DRPCListenAddr)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	var httpsListener, drpcTLSListener net.Listener
	if tlsConfig != nil {
		httpsListener, err = tls.Listen("tcp", config.ListenAddrTLS, tlsConfig)
		if err != nil {
			return nil, errs.Wrap(err)
		}
		drpcTLSListener, err = tls.Listen("tcp", config.DRPCListenAddrTLS, tlsConfig)
		if err != nil {
			return nil, errs.Wrap(err)
		}
	}

	return &Peer{
		log: log,
		kv:  kv,
		adb: adb,
		res: res,

		handler:       handler,
		httpListener:  httpListener,
		httpsListener: httpsListener,

		drpcServer:      drpcServer,
		drpcListener:    drpcListener,
		drpcTLSListener: drpcTLSListener,

		config:         config,
		areSatsDynamic: areSatsDynamic,
		endpoint:       endpoint,
		tlsConfig:      tlsConfig,

		satelliteListReload:   sync2.NewCycle(config.CacheExpiration),
		unusedRecordsDeletion: sync2.NewCycle(config.DeleteUnused.Interval),
	}, nil
}

// LogRequests logs requests.
func LogRequests(log *zap.Logger, h http.Handler) http.Handler {
	return whroute.HandlerFunc(h, func(w http.ResponseWriter, r *http.Request) {
		log.Info("request",
			zap.String("protocol", r.Proto),
			zap.String("method", r.Method),
			zap.String("host", r.Host),
			zap.String("user-agent", r.UserAgent()),
			zap.String("remote-ip", trustedip.GetClientIP(trustedip.NewListTrustAll(), r)),
		)
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

			logAtLevel := log.Info
			if rw.StatusCode() >= 500 {
				logAtLevel = log.Error
			}

			fields := []zapcore.Field{
				zap.String("method", r.Method),
				zap.String("host", r.Host),
				zap.Int("code", rw.StatusCode()),
				zap.String("request-id", middleware.GetRequestID(r.Context())),
				zap.String("user-agent", r.UserAgent()),
				zap.String("remote-ip", trustedip.GetClientIP(trustedip.NewListTrustAll(), r)),
				zap.Int64("content-length", r.ContentLength),
				zap.Int64("written", rw.Written()),
				zap.Duration("duration", time.Since(start)),
			}
			logAtLevel("response", fields...)
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

	if p.config.DeleteUnused.Run {
		p.unusedRecordsDeletion.Start(groupCtx, group, func(ctx context.Context) error {
			deleteUnusedRecords(
				ctx,
				p.log,
				p.adb,
				p.config.DeleteUnused.AsOfSystemInterval,
				p.config.DeleteUnused.SelectSize,
				p.config.DeleteUnused.DeleteSize)
			return nil
		})
		defer p.unusedRecordsDeletion.Close()
	}

	group.Go(func() error {
		return p.ServeHTTP(groupCtx, p.httpListener)
	})

	group.Go(func() error {
		return p.ServeDRPC(groupCtx, p.drpcListener)
	})

	group.Go(func() error {
		return p.kv.Run(groupCtx)
	})

	if p.tlsConfig == nil {
		p.log.Info("not starting DRPC+TLS and HTTPS because of missing TLS configuration")
	} else {
		group.Go(func() error {
			return p.ServeHTTP(groupCtx, p.httpsListener)
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

	return errs.Wrap(p.kv.Close())
}

// ServeHTTP starts serving HTTP clients.
func (p *Peer) ServeHTTP(ctx context.Context, listener net.Listener) (err error) {
	p.log.Info("Starting HTTP server", zap.String("address", listener.Addr().String()))

	server := http.Server{
		Handler: p.handler,
	}

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Serve(listener)
	}()

	select {
	case <-ctx.Done():
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

func reloadSatelliteList(ctx context.Context, log *zap.Logger, adb *authdb.Database, allowedSatellites []string) {
	log.Debug("Reloading allowed satellite list")
	allowedSatelliteURLs, _, err := satellitelist.LoadSatelliteURLs(ctx, allowedSatellites)
	if err != nil {
		log.Warn("Error reloading allowed satellite list", zap.Error(err))
	} else {
		adb.SetAllowedSatellites(allowedSatelliteURLs)
	}
}

func deleteUnusedRecords(
	ctx context.Context,
	log *zap.Logger,
	adb *authdb.Database,
	asOfSystemInterval time.Duration,
	selectSize, deleteSize int) {
	log.Info("Beginning of next iteration of unused records deletion chore")

	count, rounds, heads, err := adb.DeleteUnused(ctx, asOfSystemInterval, selectSize, deleteSize)
	if err != nil {
		log.Warn("Error deleting unused records", zap.Error(err))
	}

	log.Info(
		"Deleted unused records",
		zap.Int64("count", count),
		zap.Int64("rounds", rounds))

	log.Debug(
		"Heads deleted",
		zap.Array("heads", headsMapToLoggableHeads(heads)))

	monkit.Package().IntVal("authservice_deleted_unused_records_count").Observe(count)
	monkit.Package().IntVal("authservice_deleted_unused_records_rounds").Observe(rounds)
}

func headsMapToLoggableHeads(heads map[string]int64) zapcore.ArrayMarshalerFunc {
	type loggableHead struct {
		head  string
		count int64
	}

	var loggableHeads []loggableHead

	for k, v := range heads {
		loggableHeads = append(loggableHeads, loggableHead{head: k, count: v})
	}

	sort.Slice(loggableHeads, func(i, j int) bool {
		return loggableHeads[i].count > loggableHeads[j].count
	})

	return zapcore.ArrayMarshalerFunc(func(ae zapcore.ArrayEncoder) error {
		for _, h := range loggableHeads {
			if err := ae.AppendObject(zapcore.ObjectMarshalerFunc(func(oe zapcore.ObjectEncoder) error {
				oe.AddInt64(hex.EncodeToString([]byte(h.head)), h.count)
				return nil
			})); err != nil {
				return err
			}
		}
		return nil
	})
}
