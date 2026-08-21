// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package authadminclient_test

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"storj.io/common/encryption"
	"storj.io/common/grant"
	"storj.io/common/storj"
	"storj.io/common/testcontext"
	"storj.io/common/testrand"
	"storj.io/edge/internal/authadminclient"
	"storj.io/edge/internal/dbutil/pgtest"
	"storj.io/edge/pkg/auth/authdb"
	"storj.io/edge/pkg/auth/sqlauth"
)

const (
	testSatelliteURL = "1SYXsAycDPUu4z2ZksJD5fh5nTDcH3vCFHnpcVye5XuL1NrYV@s"
	testAPIKey       = "13Yqe3oHi5dcnGhMu2ru3cmePC9iEYv6nDrYMbLRh4wre1KtVA9SFwLNAuuvWwc43b9swRsrfsnrbuTHQ6TJKVt4LjGnaARN9PhxJEu"
	testAccessGrant  = "13J4Upun87ATb3T5T5sDXVeQaCzWFZeF9Ly4ELfxS5hUwTL8APEkwahTEJ1wxZjyErimiDs3kgid33kDLuYPYtwaY7Toy32mCTapfrUB814X13RiA844HPWK3QLKZb9cAoVceTowmNZXWbcUMKNbkMHCURE4hn8ZrdHPE3S86yngjvDxwKmarfGx"
)

func TestGetRecord(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	withEnvironment(ctx, t, func(ctx *testcontext.Context, t *testing.T, env *environment) {
		parsed, err := grant.ParseAccess(testAccessGrant)
		require.NoError(t, err)

		var keyHash authdb.KeyHash
		testrand.Read(keyHash[:])

		expected := &authdb.Record{
			SatelliteAddress:     string(testrand.RandAlphaNumeric(32)),
			MacaroonHead:         testrand.Bytes(32),
			EncryptedSecretKey:   testrand.Bytes(32),
			EncryptedAccessGrant: testrand.Bytes(32),
			Public:               testrand.Intn(1) == 0,
		}
		require.NoError(t, env.storage.Put(ctx, keyHash, expected))

		actual, err := env.adminClient.Get(ctx, keyHash.ToHex())
		require.NoError(t, err)
		requireRecordEqual(t, expected, &actual.Record)
		require.Equal(t, "", actual.DecryptedAccessGrant)

		encKey, err := authdb.NewEncryptionKey()
		require.NoError(t, err)
		storjKey := encKey.ToStorjKey()
		encAccessGrant, err := encryption.Encrypt([]byte(testAccessGrant), storj.EncAESGCM, &storjKey, &storj.Nonce{1})
		require.NoError(t, err)
		require.NotEqual(t, testAccessGrant, encAccessGrant)

		expected = &authdb.Record{
			SatelliteAddress:     testSatelliteURL,
			MacaroonHead:         parsed.APIKey.Head(),
			EncryptedSecretKey:   testrand.Bytes(32),
			EncryptedAccessGrant: encAccessGrant,
			Public:               true,
		}
		require.NoError(t, env.storage.Put(ctx, encKey.Hash(), expected))

		actual, err = env.adminClient.Get(ctx, encKey.ToBase32())
		require.NoError(t, err)
		requireRecordEqual(t, expected, &actual.Record)
		require.Equal(t, testAccessGrant, actual.DecryptedAccessGrant)
		require.Equal(t, testAPIKey, actual.APIKey)
		require.Equal(t, hex.EncodeToString(parsed.APIKey.Head()), actual.MacaroonHeadHex)

		noAddrClient, err := authadminclient.Open(ctx, authadminclient.Config{}, zap.NewNop())
		require.NoError(t, err)

		encKey, err = authdb.NewEncryptionKey()
		require.NoError(t, err)
		_, err = noAddrClient.Get(ctx, encKey.ToBase32())
		require.Error(t, err)
	})
}

func TestInvalidateRecord(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	withEnvironment(ctx, t, func(ctx *testcontext.Context, t *testing.T, env *environment) {
		records, keys := createFullRecords(ctx, t, env.storage, 5)

		invalidatedKey := keys[0]
		reason := "no more access"

		noAddrClient, err := authadminclient.Open(ctx, authadminclient.Config{}, zap.NewNop())
		require.NoError(t, err)
		require.Error(t, noAddrClient.Invalidate(ctx, invalidatedKey.ToHex(), ""))

		require.NoError(t, env.adminClient.Invalidate(ctx, invalidatedKey.ToHex(), reason))

		_, err = env.storage.Get(ctx, invalidatedKey)
		require.True(t, authdb.Invalid.Has(err))

		delete(records, invalidatedKey)
		verifyRecords(ctx, t, env, records)

		record, err := env.adminClient.Get(ctx, invalidatedKey.ToHex())
		require.NoError(t, err)
		require.NotNil(t, record)
		require.NotZero(t, record.InvalidatedAt)
		require.Equal(t, reason, record.InvalidationReason)
	})
}

func TestUnpublishRecord(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	withEnvironment(ctx, t, func(ctx *testcontext.Context, t *testing.T, env *environment) {
		records, keys := createFullRecords(ctx, t, env.storage, 5)

		unpublishedKey := keys[0]
		require.True(t, records[unpublishedKey].Public)

		noAddrClient, err := authadminclient.Open(ctx, authadminclient.Config{}, zap.NewNop())
		require.NoError(t, err)
		require.Error(t, noAddrClient.Unpublish(ctx, unpublishedKey.ToHex()))

		require.NoError(t, env.adminClient.Unpublish(ctx, unpublishedKey.ToHex()))

		records[unpublishedKey].Public = false
		verifyRecords(ctx, t, env, records)
	})
}

func TestDeleteRecord(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	withEnvironment(ctx, t, func(ctx *testcontext.Context, t *testing.T, env *environment) {
		records, keys := createFullRecords(ctx, t, env.storage, 5)

		deletedKey := keys[0]

		noAddrClient, err := authadminclient.Open(ctx, authadminclient.Config{}, zap.NewNop())
		require.NoError(t, err)
		require.Error(t, noAddrClient.Delete(ctx, deletedKey.ToHex()))

		require.NoError(t, env.adminClient.Delete(ctx, deletedKey.ToHex()))

		delete(records, deletedKey)
		verifyRecords(ctx, t, env, records)
	})
}

func TestResolveRecord(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	withEnvironment(ctx, t, func(ctx *testcontext.Context, t *testing.T, env *environment) {
		parsed, err := grant.ParseAccess(testAccessGrant)
		require.NoError(t, err)

		encKey, err := authdb.NewEncryptionKey()
		require.NoError(t, err)
		sk := encKey.ToStorjKey()
		encAccessGrant, err := encryption.Encrypt([]byte(testAccessGrant), storj.EncAESGCM, &sk, &storj.Nonce{1})
		require.NoError(t, err)
		require.NotEqual(t, testAccessGrant, encAccessGrant)

		expiresAt := time.Unix(time.Now().Unix(), 0).Add(time.Hour).UTC()
		expected := &authdb.Record{
			SatelliteAddress:     testSatelliteURL,
			MacaroonHead:         parsed.APIKey.Head(),
			EncryptedSecretKey:   testrand.Bytes(32),
			EncryptedAccessGrant: encAccessGrant,
			ExpiresAt:            &expiresAt,
			Public:               true,
		}
		require.NoError(t, env.storage.Put(ctx, encKey.Hash(), expected))

		actual, err := env.adminClient.Resolve(ctx, encKey.Hash().ToHex())
		require.NoError(t, err)
		requireRecordEqual(t, expected, &actual.Record)
		require.Equal(t, "", actual.DecryptedAccessGrant)
		require.Equal(t, "", actual.APIKey)
		require.Equal(t, hex.EncodeToString(parsed.APIKey.Head()), actual.MacaroonHeadHex)

		actual, err = env.adminClient.Resolve(ctx, encKey.ToBase32())
		require.NoError(t, err)
		requireRecordEqual(t, expected, &actual.Record)
		require.Equal(t, testAccessGrant, actual.DecryptedAccessGrant)
		require.Equal(t, testAPIKey, actual.APIKey)
		require.Equal(t, hex.EncodeToString(parsed.APIKey.Head()), actual.MacaroonHeadHex)

		noAddrClient, err := authadminclient.Open(ctx, authadminclient.Config{}, zap.NewNop())
		require.NoError(t, err)

		record, err := noAddrClient.Resolve(ctx, testAccessGrant)
		require.NoError(t, err)
		require.Equal(t, testSatelliteURL, record.SatelliteAddress)
		require.Equal(t, []byte(nil), record.EncryptedAccessGrant)
		require.Equal(t, testAccessGrant, record.DecryptedAccessGrant)
		require.Equal(t, testAPIKey, record.APIKey)
		require.Equal(t, parsed.APIKey.Head(), record.MacaroonHead)
		require.Equal(t, hex.EncodeToString(parsed.APIKey.Head()), record.MacaroonHeadHex)
		require.Nil(t, record.ExpiresAt)
	})
}

// TestMigrationDestination covers a client configured with both databases of
// an in-progress sqlmigration: mutations must reach both, since the backfill
// never updates what it has already copied into the destination, and reads
// must prefer the destination, matching how the backend resolves a record.
func TestMigrationDestination(t *testing.T) {
	connstr := pgtest.PickPostgres(t)
	ctx := testcontext.New(t)
	defer ctx.Cleanup()
	logger := zaptest.NewLogger(t)

	srcDB, err := pgtest.OpenUnique(ctx, connstr, t.Name()+"_src")
	require.NoError(t, err)
	defer ctx.Check(srcDB.Close)
	dstDB, err := pgtest.OpenUnique(ctx, connstr, t.Name()+"_dst")
	require.NoError(t, err)
	defer ctx.Check(dstDB.Close)

	src, err := sqlauth.Open(ctx, logger, srcDB.ConnStr, sqlauth.Options{ApplicationName: "test"})
	require.NoError(t, err)
	defer ctx.Check(src.Close)
	require.NoError(t, src.MigrateToLatest(ctx))

	dst, err := sqlauth.Open(ctx, logger, dstDB.ConnStr, sqlauth.Options{ApplicationName: "test"})
	require.NoError(t, err)
	defer ctx.Check(dst.Close)
	require.NoError(t, dst.MigrateToLatest(ctx))

	admin, err := authadminclient.Open(ctx, authadminclient.Config{
		SQL:                     sqlauth.Config{URL: srcDB.ConnStr},
		SQLMigrationDestination: sqlauth.Config{URL: dstDB.ConnStr},
	}, logger)
	require.NoError(t, err)
	defer ctx.Check(admin.Close)

	newRecord := func() *authdb.Record {
		return &authdb.Record{
			SatelliteAddress:     testSatelliteURL,
			MacaroonHead:         testrand.Bytes(32),
			EncryptedSecretKey:   testrand.Bytes(32),
			EncryptedAccessGrant: testrand.Bytes(32),
			Public:               true,
		}
	}

	// a key the backfill has already copied, so it exists in both databases.
	var copied authdb.KeyHash
	testrand.Read(copied[:])
	rec := newRecord()
	require.NoError(t, src.Put(ctx, copied, rec))
	require.NoError(t, dst.Put(ctx, copied, rec))

	// invalidating it must take effect in the destination too, otherwise the
	// revoked key keeps authenticating once the destination is served from.
	require.NoError(t, admin.Invalidate(ctx, copied.ToHex(), "revoked"))
	for name, kv := range map[string]*sqlauth.KV{"source": src, "destination": dst} {
		got, err := kv.GetFullRecord(ctx, copied)
		require.NoError(t, err, name)
		require.NotNil(t, got, name)
		require.True(t, got.IsInvalid(), "%s: invalidation did not reach this database", name)
	}

	// unpublish likewise.
	var published authdb.KeyHash
	testrand.Read(published[:])
	pubRec := newRecord()
	require.NoError(t, src.Put(ctx, published, pubRec))
	require.NoError(t, dst.Put(ctx, published, pubRec))

	require.NoError(t, admin.Unpublish(ctx, published.ToHex()))
	for name, kv := range map[string]*sqlauth.KV{"source": src, "destination": dst} {
		got, err := kv.GetFullRecord(ctx, published)
		require.NoError(t, err, name)
		require.NotNil(t, got, name)
		require.False(t, got.Public, "%s: unpublish did not reach this database", name)
	}

	// and delete must not leave the row behind in the destination to be
	// resurrected at cutover.
	var deleted authdb.KeyHash
	testrand.Read(deleted[:])
	delRec := newRecord()
	require.NoError(t, src.Put(ctx, deleted, delRec))
	require.NoError(t, dst.Put(ctx, deleted, delRec))

	require.NoError(t, admin.Delete(ctx, deleted.ToHex()))
	for name, kv := range map[string]*sqlauth.KV{"source": src, "destination": dst} {
		got, err := kv.GetFullRecord(ctx, deleted)
		require.NoError(t, err, name)
		require.Nil(t, got, "%s: delete did not reach this database", name)
	}

	// reads prefer the destination: with a different record under the same
	// key in each database, the destination's is the one returned.
	var diverged authdb.KeyHash
	testrand.Read(diverged[:])
	srcRec, dstRec := newRecord(), newRecord()
	srcRec.SatelliteAddress = "src.storj.test"
	dstRec.SatelliteAddress = "dst.storj.test"
	require.NoError(t, src.Put(ctx, diverged, srcRec))
	require.NoError(t, dst.Put(ctx, diverged, dstRec))

	got, err := admin.Get(ctx, diverged.ToHex())
	require.NoError(t, err)
	require.Equal(t, dstRec.SatelliteAddress, got.SatelliteAddress)

	// a key only the source has (not yet backfilled) still resolves.
	var srcOnly authdb.KeyHash
	testrand.Read(srcOnly[:])
	srcOnlyRec := newRecord()
	require.NoError(t, src.Put(ctx, srcOnly, srcOnlyRec))

	got, err = admin.Get(ctx, srcOnly.ToHex())
	require.NoError(t, err)
	require.Equal(t, srcOnlyRec.EncryptedAccessGrant, got.EncryptedAccessGrant)
}

// TestMigrationDestinationMutationOrder pins mutations to source-then-
// destination, matching sqlmigration.Storage. A mutation must reach the
// source before the destination: a backfill worker reading the source in
// between would otherwise copy the pre-mutation row into a destination it has
// just been applied to, and nothing overwrites it afterwards.
func TestMigrationDestinationMutationOrder(t *testing.T) {
	connstr := pgtest.PickPostgres(t)
	ctx := testcontext.New(t)
	defer ctx.Cleanup()
	logger := zaptest.NewLogger(t)

	srcDB, err := pgtest.OpenUnique(ctx, connstr, t.Name()+"_src")
	require.NoError(t, err)
	defer ctx.Check(srcDB.Close)
	dstDB, err := pgtest.OpenUnique(ctx, connstr, t.Name()+"_dst")
	require.NoError(t, err)
	defer ctx.Check(dstDB.Close)

	src, err := sqlauth.Open(ctx, logger, srcDB.ConnStr, sqlauth.Options{ApplicationName: "test"})
	require.NoError(t, err)
	defer ctx.Check(src.Close)
	require.NoError(t, src.MigrateToLatest(ctx))

	dst, err := sqlauth.Open(ctx, logger, dstDB.ConnStr, sqlauth.Options{ApplicationName: "test"})
	require.NoError(t, err)
	defer ctx.Check(dst.Close)
	require.NoError(t, dst.MigrateToLatest(ctx))

	admin, err := authadminclient.Open(ctx, authadminclient.Config{
		SQL:                     sqlauth.Config{URL: srcDB.ConnStr},
		SQLMigrationDestination: sqlauth.Config{URL: dstDB.ConnStr},
	}, logger)
	require.NoError(t, err)
	defer ctx.Check(admin.Close)

	var keyHash authdb.KeyHash
	testrand.Read(keyHash[:])
	rec := &authdb.Record{
		SatelliteAddress:     testSatelliteURL,
		MacaroonHead:         testrand.Bytes(32),
		EncryptedSecretKey:   testrand.Bytes(32),
		EncryptedAccessGrant: testrand.Bytes(32),
		Public:               true,
	}
	require.NoError(t, src.Put(ctx, keyHash, rec))
	require.NoError(t, dst.Put(ctx, keyHash, rec))

	// break the source so its leg of the mutation fails. Mutations are applied
	// to every database regardless of the others failing, so the order is not
	// observable from which rows changed; it is observable from the failure,
	// which the client tags with the position of the database that produced
	// it. The source failing as position 0 is the invariant under test.
	_, err = srcDB.DB.ExecContext(ctx, `DROP TABLE records`)
	require.NoError(t, err)

	err = admin.Delete(ctx, keyHash.ToHex())
	require.Error(t, err)
	require.Contains(t, err.Error(), "0:", "source must be mutated before the destination")

	// and the destination was still mutated despite the source failing.
	got, err := dst.GetFullRecord(ctx, keyHash)
	require.NoError(t, err)
	require.Nil(t, got)
}

// TestMigrationDestinationWithoutSource covers the mirror of pointing admin
// tooling at the source alone: a destination with no source silently mutates
// only the destination, and reads still look right because the destination is
// preferred, so it is refused instead.
func TestMigrationDestinationWithoutSource(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	_, err := authadminclient.Open(ctx, authadminclient.Config{
		SQLMigrationDestination: sqlauth.Config{URL: "postgres://localhost/nonexistent"},
	}, zap.NewNop())
	require.Error(t, err)
}

func verifyRecords(
	ctx *testcontext.Context,
	t *testing.T,
	env *environment,
	records map[authdb.KeyHash]*authdb.Record,
) {
	for key, record := range records {
		actual, err := env.storage.Get(ctx, key)
		require.NoError(t, err)
		requireRecordEqual(t, record, actual)
	}
}

type environment struct {
	logger      *zap.Logger
	storage     authdb.Storage
	adminClient *authadminclient.Client
}

func withEnvironment(ctx *testcontext.Context, t *testing.T, fn func(ctx *testcontext.Context, t *testing.T, env *environment)) {
	logger := zaptest.NewLogger(t)
	defer ctx.Check(logger.Sync)

	connstr := pgtest.PickPostgres(t)

	tempDB, err := pgtest.OpenUnique(ctx, connstr, t.Name())
	require.NoError(t, err)
	defer ctx.Check(tempDB.Close)

	kv, err := sqlauth.Open(ctx, logger, tempDB.ConnStr, sqlauth.Options{ApplicationName: "test"})
	require.NoError(t, err)
	defer ctx.Check(kv.Close)
	require.NoError(t, kv.MigrateToLatest(ctx))

	admin, err := authadminclient.Open(ctx, authadminclient.Config{
		SQL: sqlauth.Config{URL: tempDB.ConnStr},
	}, logger)
	require.NoError(t, err)
	defer ctx.Check(admin.Close)

	fn(ctx, t, &environment{
		logger:      logger,
		storage:     kv,
		adminClient: admin,
	})
}

// requireRecordEqual asserts that two records are equal, ignoring the
// timezones of the records' time.Time fields.
func requireRecordEqual(t *testing.T, expected *authdb.Record, actual *authdb.Record, msgAndArgs ...any) {
	if expected == nil {
		require.Nil(t, actual, msgAndArgs...)
		return
	}
	require.NotNil(t, actual, msgAndArgs...)

	if expected.ExpiresAt == nil {
		require.Nil(t, actual.ExpiresAt)
	} else {
		require.NotNil(t, actual.ExpiresAt)
		require.WithinDuration(t, *expected.ExpiresAt, *actual.ExpiresAt, 0, msgAndArgs...)
	}

	expectedCopy, actualCopy := *expected, *actual
	expectedCopy.ExpiresAt, actualCopy.ExpiresAt = nil, nil
	require.Equal(t, expectedCopy, actualCopy)
}

// createFullRecords creates count of records with random data returning
// created records.
func createFullRecords(
	ctx *testcontext.Context,
	t testing.TB,
	storage authdb.Storage,
	count int,
) (
	records map[authdb.KeyHash]*authdb.Record,
	keys []authdb.KeyHash,
) {
	records = make(map[authdb.KeyHash]*authdb.Record)

	for range count {
		marker := testrand.RandAlphaNumeric(32)

		var keyHash authdb.KeyHash
		require.NoError(t, keyHash.SetBytes(marker))

		// TODO(artur): make expiresAt configurable or random per record.
		expiresAt := time.Unix(time.Now().Add(time.Hour).Unix(), 0)

		record := &authdb.Record{
			SatelliteAddress:     string(marker),
			MacaroonHead:         marker,
			EncryptedSecretKey:   marker,
			EncryptedAccessGrant: marker,
			ExpiresAt:            &expiresAt,
			Public:               testrand.Intn(1) == 0,
		}

		keys = append(keys, keyHash)
		records[keyHash] = record

		require.NoError(t, storage.Put(ctx, keyHash, record))
	}

	return records, keys
}
