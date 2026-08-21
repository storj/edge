// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/testcontext"
	"storj.io/common/testrand"
	"storj.io/edge/internal/dbutil/pgtest"
	"storj.io/edge/pkg/auth/authdb"
	"storj.io/edge/pkg/auth/sqlauth"
)

func TestOpenStorageUnknownScheme(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	_, err := OpenStorage(ctx, zaptest.NewLogger(t), Config{KVBackend: "nope://x"})
	require.Error(t, err)
}

func TestOpenStorageSQLMigration(t *testing.T) {
	connstr := pgtest.PickPostgres(t)
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	srcDB, err := pgtest.OpenUnique(ctx, connstr, t.Name()+"_src")
	require.NoError(t, err)
	defer ctx.Check(srcDB.Close)

	dstDB, err := pgtest.OpenUnique(ctx, connstr, t.Name()+"_dst")
	require.NoError(t, err)
	defer ctx.Check(dstDB.Close)

	// The sqlmigration backend's MigrateToLatest only creates the schema on
	// the destination and then backfills from the source, mirroring the real
	// operational scenario: the source is an existing, already-migrated sql
	// backend. So the source schema must be created out-of-band first.
	srcKV, err := sqlauth.Open(ctx, zaptest.NewLogger(t), srcDB.ConnStr, sqlauth.Options{})
	require.NoError(t, err)
	require.NoError(t, srcKV.MigrateToLatest(ctx))
	require.NoError(t, srcKV.Close())

	storage, err := OpenStorage(ctx, zaptest.NewLogger(t), Config{
		KVBackend:               "sqlmigration://",
		SQL:                     sqlauth.Config{URL: srcDB.ConnStr},
		SQLMigrationDestination: sqlauth.Config{URL: dstDB.ConnStr},
	})
	require.NoError(t, err)
	defer ctx.Check(storage.Close)

	migrator, ok := storage.(interface{ MigrateToLatest(context.Context) error })
	require.True(t, ok)
	require.NoError(t, migrator.MigrateToLatest(ctx))

	var kh authdb.KeyHash
	testrand.Read(kh[:])
	require.NoError(t, storage.Put(ctx, kh, &authdb.Record{
		SatelliteAddress:     "sat.storj.test",
		MacaroonHead:         testrand.Bytes(32),
		EncryptedSecretKey:   testrand.Bytes(32),
		EncryptedAccessGrant: testrand.Bytes(32),
	}))
	got, err := storage.Get(ctx, kh)
	require.NoError(t, err)
	require.NotNil(t, got)
}
