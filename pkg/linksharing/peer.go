// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package linksharing

import (
	"context"

	"github.com/oschwald/maxminddb-golang"
	"github.com/spacemonkeygo/monkit/v3"
	"github.com/spacemonkeygo/monkit/v3/http"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/gateway-mt/pkg/authclient"
	"storj.io/gateway-mt/pkg/httpserver"
	"storj.io/gateway-mt/pkg/linksharing/objectmap"
	"storj.io/gateway-mt/pkg/linksharing/sharing"
	"storj.io/gateway-mt/pkg/server/middleware"
)

var mon = monkit.Package()

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
	Log        *zap.Logger
	Mapper     *objectmap.IPDB
	Server     *httpserver.Server
	TXTRecords *sharing.TXTRecords
}

// New is a constructor for Linksharing Peer.
func New(log *zap.Logger, config Config) (_ *Peer, err error) {
	authClient := authclient.New(config.Handler.AuthServiceConfig)
	dns, err := sharing.NewDNSClient(config.Handler.DNSServer)
	if err != nil {
		return nil, err
	}
	txtRecords := sharing.NewTXTRecords(config.Handler.TXTRecordTTL, dns, authClient)

	peer := &Peer{
		Log:        log,
		TXTRecords: txtRecords,
	}

	if config.GeoLocationDB != "" {
		reader, err := maxminddb.Open(config.GeoLocationDB)
		if err != nil {
			return nil, errs.New("unable to open geo location db: %w", err)
		}
		peer.Mapper = objectmap.NewIPDB(reader)
	}

	handle, err := sharing.NewHandler(log, peer.Mapper, txtRecords, authClient, config.Handler)
	if err != nil {
		return nil, errs.New("unable to create handler: %w", err)
	}

	handleWithTracing := http.TraceHandler(handle, mon)
	instrumentedHandle := middleware.Metrics("linksharing", handleWithTracing)

	peer.Server, err = httpserver.New(log, instrumentedHandle, txtRecords, config.Server)
	if err != nil {
		return nil, errs.New("unable to create httpserver: %w", err)
	}

	return peer, nil
}

// Run starts the server.
func (peer *Peer) Run(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	return peer.Server.Run(ctx)
}

// Close shuts down the server and all underlying resources.
func (peer *Peer) Close() error {
	var errlist errs.Group

	if peer.Server != nil {
		errlist.Add(peer.Server.Shutdown())
	}

	if peer.Mapper != nil {
		errlist.Add(peer.Mapper.Close())
	}

	return errlist.Err()
}
