// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauthtest

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	"golang.org/x/sync/errgroup"

	"storj.io/common/testcontext"
	"storj.io/gateway-mt/pkg/auth/badgerauth"
)

// RunSingleNode tests against a single node cluster of badgerauth.
func RunSingleNode(t *testing.T, c badgerauth.Config, fn func(ctx *testcontext.Context, t *testing.T, node *badgerauth.Node)) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	if c.Address == "" {
		c.Address = "127.0.0.1:0"
	}
	if c.CertsDir == "" {
		c.InsecureDisableTLS = true
	}

	log := zaptest.NewLogger(t).Named("badgerauth")
	node, err := badgerauth.New(log, c)
	require.NoError(t, err)
	defer ctx.Check(node.Close)

	require.NoError(t, node.UnderlyingDB().Ping(ctx), "Ping")

	nodectx, nodecancel := context.WithCancel(ctx)
	var g errgroup.Group
	g.Go(func() error { return node.Run(nodectx) })
	defer ctx.Check(func() error {
		nodecancel()
		return g.Wait()
	})

	fn(ctx, t, node)
}
