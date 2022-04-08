// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauthtest

import (
	"testing"

	badger "github.com/outcaste-io/badger/v3"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/testcontext"
	"storj.io/common/testrand"
	"storj.io/gateway-mt/pkg/auth/badgerauth"
)

// RunSingleNode tests against a single node cluster of badgerauth.
func RunSingleNode(t *testing.T, c badgerauth.Config, fn func(ctx *testcontext.Context, t *testing.T, db *badger.DB, node *badgerauth.DB)) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	l := badgerauth.NewLogger(zaptest.NewLogger(t).Sugar())

	opt := badger.DefaultOptions("").WithInMemory(true).WithLogger(l)
	db, err := badger.Open(opt)
	require.NoError(t, err, "Open")

	if c.ID == nil {
		var id badgerauth.NodeID
		require.NoError(t, id.SetBytes(testrand.UUID().Bytes()))
		c.ID = id
	}

	node := badgerauth.New(db, c)
	defer ctx.Check(node.Close)

	require.NoError(t, node.Ping(ctx), "Ping")

	fn(ctx, t, db, node)
}
