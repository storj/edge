// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package startupcheck_test

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"golang.org/x/sync/errgroup"

	"storj.io/common/identity"
	"storj.io/common/identity/testidentity"
	"storj.io/common/peertls/tlsopts"
	"storj.io/common/rpc"
	"storj.io/common/storj"
	"storj.io/common/testcontext"
	"storj.io/drpc/drpcmigrate"
	"storj.io/drpc/drpcmux"
	"storj.io/drpc/drpcserver"
	"storj.io/edge/pkg/startupcheck"
)

func TestCheck(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	log := zaptest.NewLogger(t)

	node1 := NewNode(t, log, testidentity.MustPregeneratedIdentity(0, storj.LatestIDVersion()))
	defer ctx.Check(node1.Close)
	ctx.Go(func() error {
		return node1.Run(ctx)
	})

	// simulate a node that won't connect by closing it off immediately.
	node2 := NewNode(t, log, testidentity.MustPregeneratedIdentity(1, storj.LatestIDVersion()))
	ctx.Check(node2.Close)

	clientIdentity := testidentity.MustPregeneratedIdentity(2, storj.LatestIDVersion())

	tempPath := t.TempDir()
	identConfig := identity.Config{
		CertPath: tempPath + "/identity.crt",
		KeyPath:  tempPath + "/identity.key",
	}

	require.NoError(t, identConfig.Save(clientIdentity))

	timeout := 10 * time.Second

	{
		check, err := startupcheck.NewNodeURLCheck(startupcheck.NodeURLCheckConfig{
			NodeURLs:       []string{"abc"},
			Logger:         log.Sugar(),
			Timeout:        timeout,
			IdentityConfig: identConfig,
		})
		require.NoError(t, err)
		require.Error(t, check.Check(ctx))
	}
	{
		check, err := startupcheck.NewNodeURLCheck(startupcheck.NodeURLCheckConfig{
			NodeURLs: []string{
				node1.NodeURL().String(),
				node2.NodeURL().String(),
			},
			Logger:         log.Sugar(),
			Timeout:        timeout,
			IdentityConfig: identConfig,
		})
		require.NoError(t, err)
		require.Error(t, check.Check(ctx))
	}
	{
		check, err := startupcheck.NewNodeURLCheck(startupcheck.NodeURLCheckConfig{
			NodeURLs:       []string{node2.NodeURL().String()},
			Logger:         log.Sugar(),
			Timeout:        timeout,
			IdentityConfig: identConfig,
		})
		require.NoError(t, err)
		require.Error(t, check.Check(ctx))
	}
	{
		check, err := startupcheck.NewNodeURLCheck(startupcheck.NodeURLCheckConfig{
			NodeURLs:       []string{"12vha9oTFnerxYRgeQ2BZqoFrLrnmmf5UWTCY2jA77dF3YvWew7@"},
			Logger:         log.Sugar(),
			IdentityConfig: identConfig,
		})
		require.NoError(t, err)
		require.NoError(t, check.Check(ctx))
	}
	{
		check, err := startupcheck.NewNodeURLCheck(startupcheck.NodeURLCheckConfig{
			NodeURLs:       []string{node1.NodeURL().String()},
			Logger:         log.Sugar(),
			Timeout:        timeout,
			IdentityConfig: identConfig,
		})
		require.NoError(t, err)
		require.NoError(t, check.Check(ctx))
	}
}

type Node struct {
	identity        *identity.FullIdentity
	mux             *drpcmigrate.ListenMux
	tcpListener     net.Listener
	drpcTLSListener net.Listener
	wg              sync.WaitGroup
	once            sync.Once
	done            chan struct{}
}

func (n *Node) Run(ctx context.Context) (err error) {
	select {
	case <-n.done:
		return errs.New("server closed")
	default:
		n.wg.Add(1)
		defer n.wg.Done()
	}

	muxCtx, muxCancel := context.WithCancel(context.Background())
	defer muxCancel()

	var muxGroup errgroup.Group

	if n.mux != nil {
		muxGroup.Go(func() error {
			return n.mux.Run(muxCtx)
		})
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var group errgroup.Group
	group.Go(func() error {
		select {
		case <-n.done:
			cancel()
		case <-ctx.Done():
		}

		return nil
	})

	if n.drpcTLSListener != nil {
		group.Go(func() error {
			defer cancel()
			return drpcserver.NewWithOptions(drpcmux.New(), drpcserver.Options{
				Manager: rpc.NewDefaultManagerOptions(),
			}).Serve(ctx, n.drpcTLSListener)
		})
	}

	err = group.Wait()

	muxCancel()
	return errs.Combine(err, muxGroup.Wait())
}

func (n *Node) Close() error {
	n.once.Do(func() { close(n.done) })
	n.wg.Wait()

	if n.tcpListener != nil {
		_ = n.tcpListener.Close()
	}
	return nil
}

func (n *Node) NodeURL() storj.NodeURL {
	return storj.NodeURL{
		ID:      n.identity.ID,
		Address: n.tcpListener.Addr().String(),
	}
}

func NewNode(t *testing.T, log *zap.Logger, identity *identity.FullIdentity) *Node {
	tlsOpts, err := tlsopts.NewOptions(identity, tlsopts.Config{
		UsePeerCAWhitelist: false,
		PeerIDVersions:     "*",
	}, nil)
	require.NoError(t, err)

	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	mux := drpcmigrate.NewListenMux(tcpListener, len(drpcmigrate.DRPCHeader))
	tlsMux := mux.Route(drpcmigrate.DRPCHeader)

	return &Node{
		identity:        identity,
		mux:             mux,
		tcpListener:     tcpListener,
		drpcTLSListener: tls.NewListener(tlsMux, tlsOpts.ServerTLSConfig()),
		done:            make(chan struct{}),
	}
}
