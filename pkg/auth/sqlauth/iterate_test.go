// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package sqlauth_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/testcontext"
	"storj.io/common/testrand"
	"storj.io/edge/internal/dbutil/pgtest"
	"storj.io/edge/pkg/auth/authdb"
	"storj.io/edge/pkg/auth/sqlauth"
)

func newRecord() *authdb.Record {
	return &authdb.Record{
		SatelliteAddress:     "sat.storj.test",
		MacaroonHead:         testrand.Bytes(32),
		EncryptedSecretKey:   testrand.Bytes(32),
		EncryptedAccessGrant: testrand.Bytes(32),
	}
}

func TestIterateAll(t *testing.T) {
	connstr := pgtest.PickPostgres(t)
	ctx := testcontext.New(t)
	defer ctx.Cleanup()
	kv, err := sqlauth.OpenTest(ctx, zaptest.NewLogger(t), t.Name(), connstr)
	require.NoError(t, err)
	defer ctx.Check(kv.Close)
	require.NoError(t, kv.MigrateToLatest(ctx))

	const n = 2500 // > one page (1000), forces multi-page iteration
	want := make(map[authdb.KeyHash]bool, n+2)
	for range n {
		var kh authdb.KeyHash
		testrand.Read(kh[:])
		require.NoError(t, kv.Put(ctx, kh, newRecord()))
		want[kh] = true
	}

	// an expired record: IterateAll must still return it (unlike Get).
	var expiredKH authdb.KeyHash
	testrand.Read(expiredKH[:])
	past := time.Now().Add(-time.Hour).UTC()
	expiredRec := newRecord()
	expiredRec.ExpiresAt = &past
	require.NoError(t, kv.Put(ctx, expiredKH, expiredRec))
	want[expiredKH] = true

	// an invalidated record: IterateAll must still return it.
	var invalidKH authdb.KeyHash
	testrand.Read(invalidKH[:])
	require.NoError(t, kv.Put(ctx, invalidKH, newRecord()))
	require.NoError(t, kv.Invalidate(ctx, invalidKH, "revoked"))
	want[invalidKH] = true

	got := make(map[authdb.KeyHash]bool, len(want))
	var lastHex string
	require.NoError(t, kv.IterateAll(ctx, func(_ context.Context, kh authdb.KeyHash, r *authdb.FullRecord) error {
		require.NotNil(t, r)
		require.False(t, got[kh], "duplicate key %x", kh)
		got[kh] = true
		require.Greater(t, kh.ToHex(), lastHex, "not in ascending key-hash order")
		lastHex = kh.ToHex()
		return nil
	}))

	require.Equal(t, want, got)
}

func TestIterateRange(t *testing.T) {
	connstr := pgtest.PickPostgres(t)
	ctx := testcontext.New(t)
	defer ctx.Cleanup()
	kv, err := sqlauth.OpenTest(ctx, zaptest.NewLogger(t), t.Name(), connstr)
	require.NoError(t, err)
	defer ctx.Check(kv.Close)
	require.NoError(t, kv.MigrateToLatest(ctx))

	const n = 500
	all := make([]authdb.KeyHash, 0, n)
	for range n {
		var kh authdb.KeyHash
		testrand.Read(kh[:])
		require.NoError(t, kv.Put(ctx, kh, newRecord()))
		all = append(all, kh)
	}

	// Scan 16 disjoint partitions of the key-hash space (single-byte
	// boundaries; Postgres bytea comparison is lexicographic and treats a
	// shorter byte string that's a prefix of a longer one as "less", so a
	// 1-byte boundary correctly splits 32-byte hashes by their leading
	// byte) and confirm together they recover every row exactly once.
	const partitions = 16
	seen := make(map[authdb.KeyHash]int)
	for i := range partitions {
		var lo, hi []byte
		if i > 0 {
			lo = []byte{byte(i * 256 / partitions)}
		}
		if i < partitions-1 {
			hi = []byte{byte((i + 1) * 256 / partitions)}
		}
		require.NoError(t, kv.IterateRange(ctx, lo, hi, func(_ context.Context, kh authdb.KeyHash, _ *authdb.FullRecord) error {
			seen[kh]++
			return nil
		}))
	}

	require.Len(t, seen, n)
	for _, kh := range all {
		require.Equal(t, 1, seen[kh], "key %x not seen exactly once", kh)
	}
}
