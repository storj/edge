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
	"storj.io/edge/pkg/auth/authdb"
	"storj.io/edge/pkg/auth/spannerauth"
	"storj.io/edge/pkg/auth/spannerauth/spannerauthtest"
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

	server, err := spannerauthtest.ConfigureTestServer(ctx, logger)
	require.NoError(t, err)
	defer server.Close()

	spannerCfg := spannerauth.Config{
		DatabaseName: "projects/P/instances/I/databases/D",
		Address:      server.Addr,
	}

	client, err := spannerauth.Open(ctx, logger, spannerCfg)
	require.NoError(t, err)
	defer ctx.Check(client.Close)

	admin, err := authadminclient.Open(ctx, authadminclient.Config{
		Spanner: spannerCfg,
	}, logger)
	require.NoError(t, err)
	defer ctx.Check(admin.Close)

	fn(ctx, t, &environment{
		logger:      logger,
		storage:     client,
		adminClient: admin,
	})
}

// requireRecordEqual asserts that two records are equal, ignoring the
// timezones of the records' time.Time fields.
func requireRecordEqual(t *testing.T, expected *authdb.Record, actual *authdb.Record, msgAndArgs ...interface{}) {
	if expected == nil {
		require.Nil(t, actual, msgAndArgs)
		return
	}
	require.NotNil(t, actual, msgAndArgs)

	if expected.ExpiresAt == nil {
		require.Nil(t, actual.ExpiresAt)
	} else {
		require.NotNil(t, actual.ExpiresAt)
		require.WithinDuration(t, *expected.ExpiresAt, *actual.ExpiresAt, 0, msgAndArgs)
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

	for i := 0; i < count; i++ {
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
