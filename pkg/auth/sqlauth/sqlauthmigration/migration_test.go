// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package sqlauthmigration_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/testcontext"
	"storj.io/common/testrand"
	"storj.io/edge/internal/dbutil/pgtest"
	"storj.io/edge/pkg/auth/authdb"
	"storj.io/edge/pkg/auth/spannerauth"
	"storj.io/edge/pkg/auth/spannerauth/spannerauthtest"
	"storj.io/edge/pkg/auth/sqlauth"
	"storj.io/edge/pkg/auth/sqlauth/sqlauthmigration"
)

func TestMigrationProxy(t *testing.T) {
	connstr := pgtest.PickPostgres(t)
	ctx := testcontext.New(t)
	defer ctx.Cleanup()
	log := zaptest.NewLogger(t)

	server, err := spannerauthtest.ConfigureTestServer(ctx, log)
	require.NoError(t, err)
	defer server.Close()
	src, err := spannerauth.Open(ctx, log, spannerauth.Config{
		DatabaseName: "projects/P/instances/I/databases/D", Address: server.Addr})
	require.NoError(t, err)
	dst, err := sqlauth.OpenTest(ctx, log, t.Name(), connstr)
	require.NoError(t, err)
	require.NoError(t, dst.MigrateToLatest(ctx))

	m := sqlauthmigration.New(log, src, dst)
	defer func() { require.NoError(t, m.Close()) }()

	var kh authdb.KeyHash
	testrand.Read(kh[:])
	rec := &authdb.Record{SatelliteAddress: "s", MacaroonHead: testrand.Bytes(32),
		EncryptedSecretKey: testrand.Bytes(32), EncryptedAccessGrant: testrand.Bytes(32)}
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

func TestMigrateToLatest(t *testing.T) {
	connstr := pgtest.PickPostgres(t)
	ctx := testcontext.New(t)
	defer ctx.Cleanup()
	log := zaptest.NewLogger(t)
	server, err := spannerauthtest.ConfigureTestServer(ctx, log)
	require.NoError(t, err)
	defer server.Close()
	src, err := spannerauth.Open(ctx, log, spannerauth.Config{
		DatabaseName: "projects/P/instances/I/databases/D", Address: server.Addr})
	require.NoError(t, err)
	dst, err := sqlauth.OpenTest(ctx, log, t.Name(), connstr)
	require.NoError(t, err)

	var kh authdb.KeyHash
	testrand.Read(kh[:])
	require.NoError(t, src.Put(ctx, kh, &authdb.Record{SatelliteAddress: "s",
		MacaroonHead: testrand.Bytes(32), EncryptedSecretKey: testrand.Bytes(32),
		EncryptedAccessGrant: testrand.Bytes(32)}))

	m := sqlauthmigration.New(log, src, dst)
	defer func() { require.NoError(t, m.Close()) }()
	require.NoError(t, m.MigrateToLatest(ctx))
	require.NoError(t, m.MigrateToLatest(ctx)) // idempotent

	got, err := dst.Get(ctx, kh)
	require.NoError(t, err)
	require.NotNil(t, got)
}

func TestMigrationProxy_InvalidatedNotResurrected(t *testing.T) {
	connstr := pgtest.PickPostgres(t)
	ctx := testcontext.New(t)
	defer ctx.Cleanup()
	log := zaptest.NewLogger(t)

	server, err := spannerauthtest.ConfigureTestServer(ctx, log)
	require.NoError(t, err)
	defer server.Close()
	src, err := spannerauth.Open(ctx, log, spannerauth.Config{
		DatabaseName: "projects/P/instances/I/databases/D", Address: server.Addr})
	require.NoError(t, err)
	dst, err := sqlauth.OpenTest(ctx, log, t.Name(), connstr)
	require.NoError(t, err)
	require.NoError(t, dst.MigrateToLatest(ctx))

	m := sqlauthmigration.New(log, src, dst)
	defer func() { require.NoError(t, m.Close()) }()

	var kh authdb.KeyHash
	testrand.Read(kh[:])
	rec := &authdb.Record{SatelliteAddress: "s", MacaroonHead: testrand.Bytes(32),
		EncryptedSecretKey: testrand.Bytes(32), EncryptedAccessGrant: testrand.Bytes(32)}

	// a still-valid record exists in the spanner source.
	require.NoError(t, src.Put(ctx, kh, rec))

	// the same key was migrated to the sqlauth destination and then invalidated (revoked) there.
	require.NoError(t, dst.Put(ctx, kh, rec))
	require.NoError(t, dst.Invalidate(ctx, kh, "revoked"))

	// the proxy must surface the invalidation, not fall back to the still-valid src record.
	got, err := m.Get(ctx, kh)
	require.Error(t, err)
	require.True(t, authdb.Invalid.Has(err))
	require.Nil(t, got)
}
