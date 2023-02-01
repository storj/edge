// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"context"
	"fmt"
	"time"

	"github.com/zeebo/errs"

	"storj.io/common/identity"
	"storj.io/common/lrucache"
	"storj.io/common/pb"
	"storj.io/common/peertls/tlsopts"
	"storj.io/common/rpc"
	"storj.io/common/storj"
	"storj.io/common/useragent"
	"storj.io/private/version"
	"storj.io/uplink"
	"storj.io/uplink/private/access"
)

// TierQueryingService asks satellite if a APIKey belongs to a paid account.
type TierQueryingService struct {
	dialer rpc.Dialer
	cache  *lrucache.ExpiringLRU
}

type tierQueryResponse struct {
	paidTier bool
}

// NewTierQueryingService constructs a TierQueryingService.
func NewTierQueryingService(identConfig identity.Config, expiration time.Duration, capacity int) (*TierQueryingService, error) {
	identity, err := identConfig.Load()
	if err != nil {
		return nil, errs.Wrap(err)
	}

	config := tlsopts.Config{
		UsePeerCAWhitelist: false,
		PeerIDVersions:     "0",
	}

	options, err := tlsopts.NewOptions(identity, config, nil)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	return &TierQueryingService{
		cache: lrucache.New(lrucache.Options{
			Expiration: expiration,
			Capacity:   capacity,
		}),
		dialer: rpc.NewDefaultPooledDialer(options),
	}, nil

}

// Do fetches and caches the paid status of an account.
func (t *TierQueryingService) Do(ctx context.Context, uplinkAccess *uplink.Access, hostname string) (paidTier bool, err error) {
	v, err := t.cache.Get(access.APIKey(uplinkAccess).Serialize(), func() (interface{}, error) {
		paidTier, err := t.queryTier(ctx, uplinkAccess, hostname)
		return tierQueryResponse{paidTier}, err
	})
	if err != nil {
		return false, err
	}
	r := v.(tierQueryResponse)
	return r.paidTier, nil

}

func (t *TierQueryingService) queryTier(ctx context.Context, uplinkAccess *uplink.Access, hostname string) (paidTier bool, err error) {
	defer mon.Task()(&ctx)(&err)

	u, err := storj.ParseNodeURL(uplinkAccess.SatelliteAddress())
	if err != nil {
		return false, err
	}
	c, err := t.dialer.DialNodeURL(ctx, u)
	if err != nil {
		return false, err
	}
	defer func() { _ = c.Close() }()

	ua, err := makeUserAgent(hostname)
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

func makeUserAgent(hostname string) ([]byte, error) {
	u, err := useragent.EncodeEntries([]useragent.Entry{{
		Product: "LinkSharingService",
		Version: version.Build.Version.String(),
		Comment: fmt.Sprintf("Tier lookup requested by %q", hostname),
	}})
	if err != nil {
		return nil, err
	}
	return u, nil
}
