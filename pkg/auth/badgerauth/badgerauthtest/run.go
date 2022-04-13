// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauthtest

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/testcontext"
	"storj.io/gateway-mt/pkg/auth/badgerauth"
)

// RunSingleNode tests against a single node cluster of badgerauth.
func RunSingleNode(t *testing.T, c badgerauth.Config, fn func(ctx *testcontext.Context, t *testing.T, node *badgerauth.Node)) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	log := zaptest.NewLogger(t).Named("badgerauth")
	node, err := badgerauth.New(log, c)
	require.NoError(t, err)
	defer ctx.Check(node.Close)

	require.NoError(t, node.UnderlyingDB().Ping(ctx), "Ping")

	fn(ctx, t, node)
}
