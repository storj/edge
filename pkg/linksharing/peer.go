// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package linksharing

import (
	"context"
	"errors"

	"github.com/oschwald/maxminddb-golang"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"storj.io/common/geoip"
	"storj.io/gateway-mt/pkg/linksharing/httpserver"
	"storj.io/gateway-mt/pkg/linksharing/sharing"
)

// Config contains configurable values for sno registration Peer.
type Config struct {
	Server  httpserver.Config
	Handler sharing.Config

	// Maxmind geolocation database path.
	GeoLocationDB string
}

// Peer is the representation of a Linksharing service itself.
//
// architecture: Peer
type Peer struct {
	Log    *zap.Logger
	IPDB   *geoip.IPDB
	Server *httpserver.Server
}

// New is a constructor for Linksharing Peer.
func New(log *zap.Logger, config Config) (_ *Peer, err error) {
	peer := &Peer{
		Log: log,
	}

	if config.GeoLocationDB != "" {
		reader, err := maxminddb.Open(config.GeoLocationDB)
		if err != nil {
			return nil, errs.New("unable to open geo location db: %w", err)
		}
		peer.IPDB = geoip.NewIPDB(reader)
	}

	handle, err := sharing.NewHandler(log, peer.IPDB, config.Handler)
	if err != nil {
		return nil, errs.New("unable to create handler: %w", err)
	}

	peer.Server, err = httpserver.New(log, handle, config.Server)
	if err != nil {
		return nil, errs.New("unable to create httpserver: %w", err)
	}

	return peer, nil
}

// Run runs SNO registration service until it's either closed or it errors.
func (peer *Peer) Run(ctx context.Context) error {
	group, ctx := errgroup.WithContext(ctx)

	// start SNO registration service as a separate goroutine.
	group.Go(func() error {
		return ignoreCancel(peer.Server.Run(ctx))
	})

	return group.Wait()
}

// Close closes all underlying resources.
func (peer *Peer) Close() error {
	errlist := errs.Group{}

	if peer.Server != nil {
		errlist.Add(peer.Server.Close())
	}

	if peer.IPDB != nil {
		errlist.Add(peer.IPDB.Close())
	}

	return errlist.Err()
}

// we ignore cancellation and stopping errors since they are expected.
func ignoreCancel(err error) error {
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
