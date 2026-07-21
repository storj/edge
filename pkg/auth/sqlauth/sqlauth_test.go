// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package sqlauth_test

import (
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

func TestOpenMigrateHealth(t *testing.T) {
	connstr := pgtest.PickPostgres(t)
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	kv, err := sqlauth.OpenTest(ctx, zaptest.NewLogger(t), t.Name(), connstr)
	require.NoError(t, err)
	defer func() { require.NoError(t, kv.Close()) }()

	require.NoError(t, kv.MigrateToLatest(ctx))
	require.NoError(t, kv.HealthCheck(ctx))
}

func TestPutGet(t *testing.T) {
	connstr := pgtest.PickPostgres(t)
	ctx := testcontext.New(t)
	defer ctx.Cleanup()
	kv, err := sqlauth.OpenTest(ctx, zaptest.NewLogger(t), t.Name(), connstr)
	require.NoError(t, err)
	defer func() { require.NoError(t, kv.Close()) }()
	require.NoError(t, kv.MigrateToLatest(ctx))

	var kh authdb.KeyHash
	testrand.Read(kh[:])
	exp := time.Now().Add(time.Hour).UTC().Round(time.Second)
	rec := &authdb.Record{
		SatelliteAddress:     "sat.storj.test",
		PublicProjectID:      testrand.UUID().Bytes(),
		MacaroonHead:         testrand.Bytes(32),
		EncryptedSecretKey:   testrand.Bytes(32),
		EncryptedAccessGrant: testrand.Bytes(32),
		ExpiresAt:            &exp,
		Public:               true,
		UsageTags:            []string{"tag-a", "tag-b"},
		ProjectCreatedAt:     time.Now().UTC().Round(time.Second),
	}
	require.NoError(t, kv.Put(ctx, kh, rec))

	got, err := kv.Get(ctx, kh)
	require.NoError(t, err)
	require.NotNil(t, got)
	gotExp := got.ExpiresAt.UTC().Round(time.Second)
	got.ExpiresAt = &gotExp
	got.ProjectCreatedAt = got.ProjectCreatedAt.UTC().Round(time.Second)
	require.Equal(t, rec, got)

	// expired record is not returned
	var kh2 authdb.KeyHash
	testrand.Read(kh2[:])
	past := time.Now().Add(-time.Hour).UTC()
	require.NoError(t, kv.Put(ctx, kh2, &authdb.Record{
		SatelliteAddress: "sat", MacaroonHead: testrand.Bytes(32),
		EncryptedSecretKey: testrand.Bytes(32), EncryptedAccessGrant: testrand.Bytes(32),
		ExpiresAt: &past,
	}))
	got2, err := kv.Get(ctx, kh2)
	require.NoError(t, err)
	require.Nil(t, got2)
}

func TestPutFullRecord(t *testing.T) {
	connstr := pgtest.PickPostgres(t)
	ctx := testcontext.New(t)
	defer ctx.Cleanup()
	kv, err := sqlauth.OpenTest(ctx, zaptest.NewLogger(t), t.Name(), connstr)
	require.NoError(t, err)
	defer func() { require.NoError(t, kv.Close()) }()
	require.NoError(t, kv.MigrateToLatest(ctx))

	var kh authdb.KeyHash
	testrand.Read(kh[:])
	createdAt := time.Now().Add(-24 * time.Hour).UTC().Round(time.Second)
	invalidatedAt := time.Now().Add(-time.Hour).UTC().Round(time.Second)
	full := &authdb.FullRecord{
		Record: authdb.Record{
			SatelliteAddress:     "sat.storj.test",
			PublicProjectID:      testrand.UUID().Bytes(),
			MacaroonHead:         testrand.Bytes(32),
			EncryptedSecretKey:   testrand.Bytes(32),
			EncryptedAccessGrant: testrand.Bytes(32),
			Public:               true,
			UsageTags:            []string{"tag-a", "tag-b"},
			ProjectCreatedAt:     time.Now().UTC().Round(time.Second),
		},
		CreatedAt:          createdAt,
		InvalidationReason: "because",
		InvalidatedAt:      invalidatedAt,
	}
	require.NoError(t, kv.PutFullRecord(ctx, kh, full))

	got, err := kv.GetFullRecord(ctx, kh)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.True(t, got.CreatedAt.Equal(createdAt), "CreatedAt not preserved: got %v want %v", got.CreatedAt, createdAt)
	require.Equal(t, "because", got.InvalidationReason)
	require.True(t, got.InvalidatedAt.Equal(invalidatedAt), "InvalidatedAt not preserved: got %v want %v", got.InvalidatedAt, invalidatedAt)
	require.True(t, got.IsInvalid())
	require.Equal(t, full.SatelliteAddress, got.SatelliteAddress)
	require.Equal(t, full.PublicProjectID, got.PublicProjectID)
	require.Equal(t, full.UsageTags, got.UsageTags)

	// re-putting the same key is a duplicate, detectable via IsDuplicate.
	err = kv.PutFullRecord(ctx, kh, full)
	require.Error(t, err)
	require.True(t, sqlauth.IsDuplicate(err), "expected duplicate error, got: %v", err)
}

func TestAdmin(t *testing.T) {
	connstr := pgtest.PickPostgres(t)
	ctx := testcontext.New(t)
	defer ctx.Cleanup()
	kv, err := sqlauth.OpenTest(ctx, zaptest.NewLogger(t), t.Name(), connstr)
	require.NoError(t, err)
	defer func() { require.NoError(t, kv.Close()) }()
	require.NoError(t, kv.MigrateToLatest(ctx))

	var kh authdb.KeyHash
	testrand.Read(kh[:])
	require.NoError(t, kv.Put(ctx, kh, &authdb.Record{
		SatelliteAddress: "sat", MacaroonHead: testrand.Bytes(32),
		EncryptedSecretKey: testrand.Bytes(32), EncryptedAccessGrant: testrand.Bytes(32),
		Public: true,
	}))

	full, err := kv.GetFullRecord(ctx, kh)
	require.NoError(t, err)
	require.False(t, full.IsInvalid())
	require.True(t, full.Public)
	require.False(t, full.CreatedAt.IsZero())

	require.NoError(t, kv.Unpublish(ctx, kh))
	full, err = kv.GetFullRecord(ctx, kh)
	require.NoError(t, err)
	require.False(t, full.Public)

	require.NoError(t, kv.Invalidate(ctx, kh, "because"))
	_, err = kv.Get(ctx, kh)
	require.True(t, authdb.Invalid.Has(err))

	require.NoError(t, kv.Delete(ctx, kh))
	got, err := kv.Get(ctx, kh)
	require.NoError(t, err)
	require.Nil(t, got)
}
