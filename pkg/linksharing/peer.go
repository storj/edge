// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package linksharing

import (
	"context"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/oschwald/maxminddb-golang"
	"github.com/spacemonkeygo/monkit/v3"
	httpmon "github.com/spacemonkeygo/monkit/v3/http"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/http/requestid"
	"storj.io/edge/pkg/authclient"
	"storj.io/edge/pkg/httpserver"
	"storj.io/edge/pkg/linksharing/objectmap"
	"storj.io/edge/pkg/linksharing/sharing"
	"storj.io/edge/pkg/server/middleware"
)

var (
	mon = monkit.Package()
	// ErrInvalidConcurrentRequests is an error returned when concurrent requests is not greater than zero.
	ErrInvalidConcurrentRequests = errs.New("concurrent requests limit must be greater than zero. Check config --limits.concurrent-requests.")
)

// Config contains configurable values for Linksharing Peer.
type Config struct {
	Server  httpserver.Config
	Handler sharing.Config

	// ShutdownDelay is how long to wait until Shutdown is called. During
	// the delay the health endpoint should return 503s to allow a load
	// balancer time to re-route requests.
	ShutdownDelay time.Duration

	// Maxmind geolocation database path.
	GeoLocationDB string

	// ConcurrentRequestLimit is the number of concurrent requests allowed per project ID, or if unavailable, macaroon head.
	ConcurrentRequestLimit uint
}

// Peer is the representation of a Linksharing service itself.
//
// architecture: Peer
type Peer struct {
	Log        *zap.Logger
	Mapper     *objectmap.IPDB
	Server     *httpserver.Server
	TXTRecords *sharing.TXTRecords

	shutdownDelay time.Duration

	inShutdown int32
}

// New is a constructor for Linksharing Peer.
func New(log *zap.Logger, config Config) (_ *Peer, err error) {
	dnsClient, err := sharing.NewDNSClient(config.Handler.DNSServer)
	if err != nil {
		return nil, err
	}
	authClient := authclient.New(config.Handler.AuthServiceConfig)
	txtRecords := sharing.NewTXTRecords(config.Handler.TXTRecordTTL, dnsClient, authClient)

	peer := &Peer{
		Log:           log,
		TXTRecords:    txtRecords,
		shutdownDelay: config.ShutdownDelay,
	}

	if config.GeoLocationDB != "" {
		reader, err := maxminddb.Open(config.GeoLocationDB)
		if err != nil {
			return nil, errs.New("unable to open geo location db: %w", err)
		}
		peer.Mapper = objectmap.NewIPDB(reader)
	}

	var tqs *sharing.TierQueryingService
	if config.Server.TLSConfig != nil {
		tqs, err = sharing.NewTierQueryingService(
			config.Server.TLSConfig.TierServiceIdentity,
			config.Server.TLSConfig.TierCacheExpiration,
			config.Server.TLSConfig.TierCacheCapacity,
		)
		if err != nil {
			return nil, errs.New("unable to create tier querying service: %w", err)
		}
	}

	handle, err := sharing.NewHandler(log, peer.Mapper, txtRecords, authClient, &peer.inShutdown, config.Handler)
	if err != nil {
		return nil, errs.New("unable to create handler: %w", err)
	}

	if config.ConcurrentRequestLimit <= 0 {
		return nil, ErrInvalidConcurrentRequests
	}
	limitHandle := middleware.NewConcurrentRequestsLimiter(config.ConcurrentRequestLimit,
		func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
		},
	).Limit(handle)

	eventHandle := sharing.EventHandler(limitHandle)
	credsHandle := handle.CredentialsHandler(eventHandle)
	traceHandle := httpmon.TraceHandler(credsHandle, mon)
	metricsHandle := middleware.Metrics("linksharing", traceHandle)
	reqIDHandle := requestid.AddToContext(metricsHandle)

	var decisionFunc httpserver.CertMagicOnDemandDecisionFunc
	if config.Server.TLSConfig != nil && config.Server.TLSConfig.CertMagic {
		decisionFunc, err = customDomainsOverTLSDecisionFunc(config.Server.TLSConfig, txtRecords, tqs, dnsClient)
		if err != nil {
			return nil, errs.New("unable to get decision func for Custom Domains@TLS feature: %w", err)
		}
	}

	peer.Server, err = httpserver.New(log, reqIDHandle, decisionFunc, config.Server)
	if err != nil {
		return nil, errs.New("unable to create httpserver: %w", err)
	}

	return peer, nil
}

func customDomainsOverTLSDecisionFunc(tlsConfig *httpserver.TLSConfig, txtRecords *sharing.TXTRecords, tqs *sharing.TierQueryingService, dnsClient *sharing.DNSClient) (httpserver.CertMagicOnDemandDecisionFunc, error) {
	bases := make([]*url.URL, 0, len(tlsConfig.CertMagicPublicURLs))
	for _, base := range tlsConfig.CertMagicPublicURLs {
		parsed, err := url.Parse(base)
		if err != nil {
			return nil, errs.New("invalid public URL %q: %v", base, err)
		}
		bases = append(bases, parsed)
	}

	return func(ctx context.Context, name string) error {
		// allow configured urls
		for _, url := range bases {
			if name == url.Host {
				return nil
			}
		}
		// validate dns txt records for everyone else
		result, err := txtRecords.FetchAccessForHostNoAccessGrant(tlsConfig.Ctx, name, "")
		if err != nil {
			return err
		}
		if !result.TLS {
			return errs.New("tls not enabled")
		}
		// validate requester is a paying customer
		for _, allowed := range tlsConfig.SkipPaidTierAllowlist {
			if allowed == "*" || name == allowed {
				// skip paid tier query
				return nil
			}
		}
		paidTier, err := tqs.Do(tlsConfig.Ctx, result.Access, name)
		if err != nil {
			return err
		}
		if !paidTier {
			return errs.New("not paid tier")
		}

		// check the CNAME for the domain is pointing to here so challenges from the CA don't fail.
		if err := dnsClient.ValidateCNAME(tlsConfig.Ctx, name, bases); err != nil {
			return err
		}

		// request cert
		return nil
	}, nil
}

// Run starts the server.
func (peer *Peer) Run(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	return peer.Server.Run(ctx)
}

// Close shuts down the server and all underlying resources.
func (peer *Peer) Close() error {
	var errlist errs.Group

	atomic.StoreInt32(&peer.inShutdown, 1)
	if peer.shutdownDelay > 0 {
		peer.Log.Info("Waiting before server shutdown:", zap.Duration("Delay", peer.shutdownDelay))
		time.Sleep(peer.shutdownDelay)
	}

	if peer.Server != nil {
		errlist.Add(peer.Server.Shutdown())
	}

	if peer.Mapper != nil {
		errlist.Add(peer.Mapper.Close())
	}

	return errlist.Err()
}
