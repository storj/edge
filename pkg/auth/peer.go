// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package auth

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
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

	"storj.io/common/pb"
	"storj.io/common/sync2"
	"storj.io/gateway-mt/pkg/auth/authdb"
	"storj.io/gateway-mt/pkg/auth/drpcauth"
	"storj.io/gateway-mt/pkg/auth/failrate"
	"storj.io/gateway-mt/pkg/auth/httpauth"
	"storj.io/gateway-mt/pkg/auth/satellitelist"
)

const serverShutdownTimeout = 10 * time.Second

// Config holds authservice's configuration.
type Config struct {
	Endpoint                     string        `help:"Gateway endpoint URL to return to clients" default:""`
	AuthToken                    string        `help:"auth security token to validate requests" releaseDefault:"" devDefault:""`
	AllowedSatellites            []string      `help:"list of satellite NodeURLs allowed for incoming access grants" default:"https://www.storj.io/dcs-satellites"`
	CacheExpiration              time.Duration `help:"length of time satellite addresses are cached for" default:"10m"`
	GetAccessRateLimiters        failrate.LimitersConfig
	GetAccessRateLimitersEnabled bool `help:"indicates if rate-limiting for GetAccess endpoints is enabled" default:"false"`

	KVBackend string `help:"key/value store backend url" default:""`
	Migration bool   `help:"create or update the database schema, and then continue service startup" default:"false"`

	ListenAddr    string `user:"true" help:"public HTTP address to listen on" default:":8000"`
	ListenAddrTLS string `user:"true" help:"public HTTPS address to listen on" default:":8443"`

	DRPCListenAddr    string `user:"true" help:"public DRPC address to listen on" default:":6666"`
	DRPCListenAddrTLS string `user:"true" help:"public DRPC+TLS address to listen on" default:":7777"`

	LetsEncrypt bool   `user:"true" help:"use lets-encrypt to handle TLS certificates" default:"false"`
	CertFile    string `user:"true" help:"server certificate file" default:""`
	KeyFile     string `user:"true" help:"server key file" default:""`
	PublicURL   string `user:"true" help:"public url for the server, for the TLS certificate" devDefault:"http://localhost:8080" releaseDefault:""`

	DeleteUnused DeleteUnusedConfig
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
	log        *zap.Logger
	kv         authdb.KV
	adb        *authdb.Database
	res        *httpauth.Resources
	httpServer *http.Server
	drpcServer pb.DRPCEdgeAuthServer

	config         Config
	areSatsDynamic bool
	endpoint       *url.URL
	tlsConfig      *tls.Config

	satelliteListReload   *sync2.Cycle
	unusedRecordsDeletion *sync2.Cycle

	// TODO(artur, erik): having stopDRPCAuth is a little unusual compared to other
	// dependencies that have, e.g. Close method. We should align drpcauth to match
	// that behaviour.
	stopDRPCAuth context.CancelFunc
}

// New constructs new Peer.
func New(ctx context.Context, log *zap.Logger, config Config, configDir string) (*Peer, error) {
	if len(config.AllowedSatellites) == 0 {
		return nil, errs.New("allowed satellites parameter '--allowed-satellites' is required")
	}
	allowedSats, areSatsDynamic, err := satellitelist.LoadSatelliteIDs(ctx, config.AllowedSatellites)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	if len(allowedSats) == 0 {
		return nil, errs.New("allowed satellites parameter '--allowed-satellites' resolved to zero satellites")
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

	kv, err := OpenKV(ctx, log.Named("db"), config.KVBackend)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	adb := authdb.NewDatabase(kv, allowedSats)

	var rl *failrate.Limiters
	if config.GetAccessRateLimitersEnabled {
		rl, err = failrate.NewLimiters(config.GetAccessRateLimiters)
		if err != nil {
			return nil, err
		}
	}

	res := httpauth.New(log.Named("resources"), adb, endpoint, config.AuthToken, rl)

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
	handler = LogResponses(log, LogRequests(log, handler))

	httpServer := &http.Server{
		Addr:    config.ListenAddr,
		Handler: handler,
	}

	drpcServer := drpcauth.NewServer(log, adb, endpoint)

	return &Peer{
		log:        log,
		kv:         kv,
		adb:        adb,
		res:        res,
		httpServer: httpServer,
		drpcServer: drpcServer,

		config:         config,
		areSatsDynamic: areSatsDynamic,
		endpoint:       endpoint,
		tlsConfig:      tlsConfig,

		satelliteListReload:   sync2.NewCycle(config.CacheExpiration),
		unusedRecordsDeletion: sync2.NewCycle(config.DeleteUnused.Interval),

		stopDRPCAuth: func() {},
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
				zap.String("user-agent", r.UserAgent()),
				zap.Int64("content-length", r.ContentLength),
				zap.Int64("written", rw.Written()),
				zap.Duration("duration", time.Since(start)),
			}
			logAtLevel("response", fields...)
		}))
}

// Run starts authservice.
func (p *Peer) Run(ctx context.Context) error {
	group, groupCtx := errgroup.WithContext(ctx)

	if p.areSatsDynamic {
		p.satelliteListReload.Start(groupCtx, group, func(ctx context.Context) error {
			reloadSatelliteList(ctx, p.log, p.adb, p.config.AllowedSatellites)
			return nil
		})
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
	}

	ctxWithCancel, cancel := context.WithCancel(groupCtx)

	p.stopDRPCAuth = cancel

	group.Go(func() error {
		httpListener, err := net.Listen("tcp", p.config.ListenAddr)
		if err != nil {
			return err
		}

		return p.ServeHTTP(httpListener)
	})

	group.Go(func() error {
		drpcListener, err := net.Listen("tcp", p.config.DRPCListenAddr)
		if err != nil {
			return err
		}

		return p.ServeDRPC(ctxWithCancel, drpcListener)
	})

	if p.tlsConfig == nil {
		p.log.Info("not starting DRPC+TLS and HTTPS because of missing TLS configuration")
	} else {
		group.Go(func() error {
			httpsListener, err := tls.Listen("tcp", p.config.ListenAddrTLS, p.tlsConfig)
			if err != nil {
				return err
			}

			return p.ServeHTTP(httpsListener)
		})

		group.Go(func() error {
			drpcTLSListener, err := tls.Listen("tcp", p.config.DRPCListenAddrTLS, p.tlsConfig)
			if err != nil {
				return err
			}

			return p.ServeDRPC(ctxWithCancel, drpcTLSListener)
		})
	}

	p.res.SetStartupDone()

	return errs.Wrap(group.Wait())
}

// Close closes all authservice's resources. It must not be called concurrently.
func (p *Peer) Close() error {
	p.stopDRPCAuth()

	p.satelliteListReload.Close()
	p.unusedRecordsDeletion.Close()

	// Don't wait more than a couple of seconds to shut down the HTTP server.
	ctx, canc := context.WithTimeout(context.Background(), serverShutdownTimeout)
	defer canc()

	return errs.Combine(
		errs.Wrap(p.httpServer.Shutdown(ctx)),
		errs.Wrap(p.kv.Close()),
	)
}

// ServeHTTP starts serving HTTP clients.
func (p *Peer) ServeHTTP(listener net.Listener) error {
	p.log.Info("Starting HTTP server", zap.String("address", listener.Addr().String()))
	err := p.httpServer.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// ServeDRPC starts serving DRPC clients.
func (p *Peer) ServeDRPC(ctx context.Context, listener net.Listener) error {
	p.log.Info("Starting DRPC server", zap.String("address", listener.Addr().String()))

	return drpcauth.StartListen(ctx, p.drpcServer, listener)
}

func reloadSatelliteList(ctx context.Context, log *zap.Logger, adb *authdb.Database, allowedSatellites []string) {
	log.Debug("Reloading allowed satellite list")
	allowedSatelliteIDs, _, err := satellitelist.LoadSatelliteIDs(ctx, allowedSatellites)
	if err != nil {
		log.Warn("Error reloading allowed satellite list", zap.Error(err))
	} else {
		adb.SetAllowedSatellites(allowedSatelliteIDs)
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
		zap.Int64("rounds", rounds),
		zap.Array("heads", headsMapToLoggableHeads(heads)))

	monkit.Package().IntVal("authservice_deleted_unused_records_count").Observe(count)
	monkit.Package().IntVal("authservice_deleted_unused_records_rounds").Observe(rounds)

	for h, c := range heads {
		monkit.Package().IntVal(
			"authservice_deleted_unused_records_deletes_per_head",
			monkit.NewSeriesTag("head", hex.EncodeToString([]byte(h))),
		).Observe(c)
	}
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
