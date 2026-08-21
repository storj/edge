// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package sqlmigration_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	"golang.org/x/sync/errgroup"

	"storj.io/common/testcontext"
	"storj.io/common/testrand"
	"storj.io/edge/internal/dbutil/pgtest"
	"storj.io/edge/pkg/auth/authdb"
	"storj.io/edge/pkg/auth/sqlauth"
	"storj.io/edge/pkg/auth/sqlauth/sqlmigration"
)

func newRecord() *authdb.Record {
	return &authdb.Record{
		SatelliteAddress:     "sat.storj.test",
		MacaroonHead:         testrand.Bytes(32),
		EncryptedSecretKey:   testrand.Bytes(32),
		EncryptedAccessGrant: testrand.Bytes(32),
	}
}

// newTestPair returns a migrated source and destination KV against two
// unique temporary databases on the same test Postgres server.
func newTestPair(t *testing.T, ctx *testcontext.Context) (src, dst *sqlauth.KV) {
	connstr := pgtest.PickPostgres(t)
	log := zaptest.NewLogger(t)

	src, err := sqlauth.OpenTest(ctx, log, t.Name()+"_src", connstr)
	require.NoError(t, err)
	require.NoError(t, src.MigrateToLatest(ctx))

	dst, err = sqlauth.OpenTest(ctx, log, t.Name()+"_dst", connstr)
	require.NoError(t, err)
	require.NoError(t, dst.MigrateToLatest(ctx))

	return src, dst
}

func TestMigrationProxy(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()
	src, dst := newTestPair(t, ctx)
	defer ctx.Check(src.Close)
	defer ctx.Check(dst.Close)

	m := sqlmigration.New(zaptest.NewLogger(t), src, dst, sqlmigration.Options{})
	defer ctx.Check(m.Close)

	var kh authdb.KeyHash
	testrand.Read(kh[:])
	rec := newRecord()
	require.NoError(t, m.Put(ctx, kh, rec))

	// present in dst
	got, err := dst.Get(ctx, kh)
	require.NoError(t, err)
	require.NotNil(t, got)

	// dst-miss falls back to src
	var kh2 authdb.KeyHash
	testrand.Read(kh2[:])
	require.NoError(t, src.Put(ctx, kh2, rec))
	got2, err := m.Get(ctx, kh2)
	require.NoError(t, err)
	require.NotNil(t, got2)
}

func TestMigrationProxy_InvalidatedNotResurrected(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()
	src, dst := newTestPair(t, ctx)
	defer ctx.Check(src.Close)
	defer ctx.Check(dst.Close)

	m := sqlmigration.New(zaptest.NewLogger(t), src, dst, sqlmigration.Options{})
	defer ctx.Check(m.Close)

	var kh authdb.KeyHash
	testrand.Read(kh[:])
	rec := newRecord()

	// a still-valid record exists in the source.
	require.NoError(t, src.Put(ctx, kh, rec))

	// the same key was migrated to the destination and then invalidated there.
	require.NoError(t, dst.Put(ctx, kh, rec))
	require.NoError(t, dst.Invalidate(ctx, kh, "revoked"))

	// the proxy must surface the invalidation, not fall back to the still-valid src record.
	got, err := m.Get(ctx, kh)
	require.Error(t, err)
	require.True(t, authdb.Invalid.Has(err))
	require.Nil(t, got)
}

func TestMigrateToLatestCreatesDestinationSchema(t *testing.T) {
	connstr := pgtest.PickPostgres(t)
	ctx := testcontext.New(t)
	defer ctx.Cleanup()
	log := zaptest.NewLogger(t)

	src, err := sqlauth.OpenTest(ctx, log, t.Name()+"_src", connstr)
	require.NoError(t, err)
	defer ctx.Check(src.Close)
	require.NoError(t, src.MigrateToLatest(ctx))

	dst, err := sqlauth.OpenTest(ctx, log, t.Name()+"_dst", connstr)
	require.NoError(t, err)
	defer ctx.Check(dst.Close)
	// dst is intentionally left unmigrated here.

	m := sqlmigration.New(log, src, dst, sqlmigration.Options{})
	defer ctx.Check(m.Close)

	require.NoError(t, m.MigrateToLatest(ctx))

	// dst's schema now exists: a direct Put against it succeeds.
	var kh authdb.KeyHash
	testrand.Read(kh[:])
	require.NoError(t, dst.Put(ctx, kh, newRecord()))
}

// TestMigrationProxy_GetFullRecord covers GetFullRecord's deliberately
// asymmetric fallback semantics versus Get: it falls back from destination to
// source only on a clean (nil,nil) miss, and does NOT fall back on an
// unexpected destination error.
func TestMigrationProxy_GetFullRecord(t *testing.T) {
	// subtest names are kept short: they get appended to "_src"/"_dst" and
	// passed to Postgres as a database name, which silently truncates
	// identifiers over 63 bytes, so a long subtest name could truncate away
	// the "_src"/"_dst" suffix entirely and collide the two databases.
	t.Run("hit", func(t *testing.T) {
		ctx := testcontext.New(t)
		defer ctx.Cleanup()
		src, dst := newTestPair(t, ctx)
		defer ctx.Check(src.Close)
		defer ctx.Check(dst.Close)

		m := sqlmigration.New(zaptest.NewLogger(t), src, dst, sqlmigration.Options{})
		defer ctx.Check(m.Close)

		var kh authdb.KeyHash
		testrand.Read(kh[:])

		// put conflicting records under the same key in both backends so that
		// returning the destination's version (and not the source's) is
		// verifiable, not just a side effect of the source being empty.
		dstRec := newRecord()
		dstRec.SatelliteAddress = "dst.storj.test"
		srcRec := newRecord()
		srcRec.SatelliteAddress = "src.storj.test"
		require.NoError(t, dst.Put(ctx, kh, dstRec))
		require.NoError(t, src.Put(ctx, kh, srcRec))

		got, err := m.GetFullRecord(ctx, kh)
		require.NoError(t, err)
		require.NotNil(t, got)
		require.Equal(t, dstRec.SatelliteAddress, got.SatelliteAddress)
	})

	t.Run("miss", func(t *testing.T) {
		ctx := testcontext.New(t)
		defer ctx.Cleanup()
		src, dst := newTestPair(t, ctx)
		defer ctx.Check(src.Close)
		defer ctx.Check(dst.Close)

		m := sqlmigration.New(zaptest.NewLogger(t), src, dst, sqlmigration.Options{})
		defer ctx.Check(m.Close)

		var kh authdb.KeyHash
		testrand.Read(kh[:])
		rec := newRecord()
		require.NoError(t, src.Put(ctx, kh, rec))

		got, err := m.GetFullRecord(ctx, kh)
		require.NoError(t, err)
		require.NotNil(t, got)
		require.Equal(t, rec.SatelliteAddress, got.SatelliteAddress)
	})

	t.Run("error", func(t *testing.T) {
		ctx := testcontext.New(t)
		defer ctx.Cleanup()
		src, dst := newTestPair(t, ctx)
		defer ctx.Check(src.Close)
		// dst is closed explicitly below; KV.Close is idempotent, so closing
		// it again here in cleanup is safe.
		defer ctx.Check(dst.Close)

		m := sqlmigration.New(zaptest.NewLogger(t), src, dst, sqlmigration.Options{})
		defer ctx.Check(m.Close)

		var kh authdb.KeyHash
		testrand.Read(kh[:])
		rec := newRecord()
		require.NoError(t, src.Put(ctx, kh, rec))

		// force a genuine (non sql.ErrNoRows) destination error by closing
		// dst's connection before querying it.
		require.NoError(t, dst.Close())

		got, err := m.GetFullRecord(ctx, kh)
		require.Error(t, err)
		require.Nil(t, got)
	})
}

func TestMigrateToLatest(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()
	src, dst := newTestPair(t, ctx)
	defer ctx.Check(src.Close)
	defer ctx.Check(dst.Close)

	var kh authdb.KeyHash
	testrand.Read(kh[:])
	require.NoError(t, src.Put(ctx, kh, newRecord()))

	m := sqlmigration.New(zaptest.NewLogger(t), src, dst, sqlmigration.Options{})
	defer ctx.Check(m.Close)
	require.NoError(t, m.MigrateToLatest(ctx))
	require.NoError(t, m.MigrateToLatest(ctx)) // idempotent

	got, err := dst.Get(ctx, kh)
	require.NoError(t, err)
	require.NotNil(t, got)
}

func TestMigrateToLatestConcurrent(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()
	src, dst := newTestPair(t, ctx)
	defer ctx.Check(src.Close)
	defer ctx.Check(dst.Close)

	const n = 2000
	keys := make([]authdb.KeyHash, n)
	for i := range keys {
		testrand.Read(keys[i][:])
		require.NoError(t, src.Put(ctx, keys[i], newRecord()))
	}

	m := sqlmigration.New(zaptest.NewLogger(t), src, dst, sqlmigration.Options{Concurrency: 8, BatchSize: 100})
	defer ctx.Check(m.Close)

	require.NoError(t, m.MigrateToLatest(ctx))
	require.NoError(t, m.MigrateToLatest(ctx)) // idempotent, across all partitions

	for _, kh := range keys {
		got, err := dst.Get(ctx, kh)
		require.NoError(t, err)
		require.NotNil(t, got, "key %x missing from destination after backfill", kh)
	}
}

func TestMigrateToLatestRacesWithLivePut(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()
	src, dst := newTestPair(t, ctx)
	defer ctx.Check(src.Close)
	defer ctx.Check(dst.Close)

	m := sqlmigration.New(zaptest.NewLogger(t), src, dst, sqlmigration.Options{Concurrency: 4, BatchSize: 50})
	defer ctx.Check(m.Close)

	// a key already migrated into dst and then invalidated there; its stale
	// (still-valid) copy remains in src, as a backfill pass would see it.
	var invalidatedKH authdb.KeyHash
	testrand.Read(invalidatedKH[:])
	rec := newRecord()
	require.NoError(t, src.Put(ctx, invalidatedKH, rec))
	require.NoError(t, dst.Put(ctx, invalidatedKH, rec))
	require.NoError(t, dst.Invalidate(ctx, invalidatedKH, "revoked"))

	// more source-only rows so the backfill has real work to overlap with
	// the concurrent live traffic below.
	const n = 2000
	for range n {
		var kh authdb.KeyHash
		testrand.Read(kh[:])
		require.NoError(t, src.Put(ctx, kh, newRecord()))
	}

	var group errgroup.Group
	group.Go(func() error {
		return m.MigrateToLatest(ctx)
	})
	for range 50 {
		var kh authdb.KeyHash
		testrand.Read(kh[:])
		group.Go(func() error {
			return m.Put(ctx, kh, newRecord())
		})
	}
	require.NoError(t, group.Wait())

	// the invalidation must survive: ON CONFLICT DO NOTHING must not let a
	// stale, still-valid copy of an already-invalidated key resurrect it.
	got, err := m.Get(ctx, invalidatedKH)
	require.Error(t, err)
	require.True(t, authdb.Invalid.Has(err))
	require.Nil(t, got)
}
