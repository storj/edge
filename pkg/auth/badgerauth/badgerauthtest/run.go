// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauthtest

import (
	"testing"
	"time"

	badger "github.com/outcaste-io/badger/v3"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/testcontext"
	"storj.io/gateway-mt/pkg/auth/badgerauth"
)

// RunSingleNode tests against a single node cluster of badgerauth.
func RunSingleNode(t *testing.T, tombstoneExpiration time.Duration, fn func(ctx *testcontext.Context, t *testing.T, db *badger.DB, node *badgerauth.Node)) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	l := badgerauth.NewLogger(zaptest.NewLogger(t).Sugar())

	opt := badger.DefaultOptions("").WithInMemory(true).WithLogger(l)
	db, err := badger.Open(opt)
	require.NoError(t, err, "Open")

	node := badgerauth.NewTestNode(db, tombstoneExpiration)
	defer ctx.Check(node.Close)

	require.NoError(t, node.Ping(ctx), "Ping")

	fn(ctx, t, db, node)
}
