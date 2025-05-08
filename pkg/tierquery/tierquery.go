// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package tierquery

import (
	"context"
	"fmt"
	"time"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"

	"storj.io/common/identity"
	"storj.io/common/pb"
	"storj.io/common/peertls/tlsopts"
	"storj.io/common/rpc"
	"storj.io/common/storj"
	"storj.io/common/useragent"
	"storj.io/common/version"
	"storj.io/edge/internal/lrucache"
	"storj.io/uplink"
	"storj.io/uplink/private/access"
)

var mon = monkit.Package()

// Config contains configuration parameters for a Service.
type Config struct {
	Identity        identity.Config
	CacheExpiration time.Duration `help:"expiration time for entries in the tier-querying service cache" default:"5m"`
	CacheCapacity   int           `help:"capacity of the tier-querying service cache" default:"10000"`
}

// Service asks satellite if a APIKey belongs to a paid account.
type Service struct {
	dialer  rpc.Dialer
	cache   *lrucache.ExpiringLRU
	product string
}

type tierQueryResponse struct {
	paidTier bool
}

// NewService constructs a Service.
func NewService(config Config, product string) (*Service, error) {
	identity, err := config.Identity.Load()
	if err != nil {
		return nil, errs.Wrap(err)
	}

	tlsConfig := tlsopts.Config{
		UsePeerCAWhitelist: false,
		PeerIDVersions:     "0",
	}

	options, err := tlsopts.NewOptions(identity, tlsConfig, nil)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	return &Service{
		cache: lrucache.New(lrucache.Options{
			Expiration: config.CacheExpiration,
			Capacity:   config.CacheCapacity,
		}),
		dialer:  rpc.NewDefaultPooledDialer(options),
		product: product,
	}, nil

}

// Do fetches and caches the paid status of an account.
func (s *Service) Do(ctx context.Context, uplinkAccess *uplink.Access, hostname string) (paidTier bool, err error) {
	v, err := s.cache.Get(ctx, access.APIKey(uplinkAccess).Serialize(), func() (interface{}, error) {
		paidTier, err := s.queryTier(ctx, uplinkAccess, hostname)
		return tierQueryResponse{paidTier}, err
	})
	if err != nil {
		return false, err
	}
	r := v.(tierQueryResponse)
	return r.paidTier, nil

}

func (s *Service) queryTier(ctx context.Context, uplinkAccess *uplink.Access, hostname string) (paidTier bool, err error) {
	defer mon.Task()(&ctx)(&err)

	u, err := storj.ParseNodeURL(uplinkAccess.SatelliteAddress())
	if err != nil {
		return false, err
	}
	c, err := s.dialer.DialNodeURL(ctx, u)
	if err != nil {
		return false, err
	}
	defer func() { _ = c.Close() }()

	ua, err := s.makeUserAgent(hostname)
	if err != nil {
		return false, err
	}

	// TODO(artur): it might be a better idea for this to make it to libuplink's
	// API.
	r, err := pb.NewDRPCUserInfoClient(c).Get(ctx, &pb.GetUserInfoRequest{
		Header: &pb.RequestHeader{
			ApiKey:    access.APIKey(uplinkAccess).SerializeRaw(),
			UserAgent: ua,
		},
	})
	if err != nil {
		return false, err
	}

	return r.PaidTier, nil
}

func (s *Service) makeUserAgent(hostname string) ([]byte, error) {
	entry := useragent.Entry{
		Product: s.product,
		Version: version.Build.Version.String(),
	}
	if hostname != "" {
		entry.Comment = fmt.Sprintf("Tier lookup requested by %q", hostname)
	}

	u, err := useragent.EncodeEntries([]useragent.Entry{entry})
	if err != nil {
		return nil, err
	}

	return u, nil
}
