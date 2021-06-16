// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package sqlauth_test

import (
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"storj.io/common/testcontext"
	"storj.io/gateway-mt/auth"
	"storj.io/private/dbutil/pgtest"
)

func TestKVFullCycle_Postgres(t *testing.T)  { testKVFullCycle(t, pgtest.PickPostgres(t)) }
func TestKVFullCycle_Cockroach(t *testing.T) { testKVFullCycle(t, pgtest.PickCockroachAlt(t)) }

func testKVFullCycle(t *testing.T, connStr string) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	kv, err := OpenTest(ctx, zap.NewNop(), t.Name(), connStr)
	require.NoError(t, err)
	defer func() { require.NoError(t, kv.Close()) }()

	require.NoError(t, kv.Ping(ctx), "ping")
	require.NoError(t, kv.MigrateToLatest(ctx), "migrateToLatest")

	randBytes := func(b []byte) {
		_, err := rand.Read(b)
		require.NoError(t, err, "randBytes")
	}
	rb := make([]byte, 32)

	var keyHash auth.KeyHash
	{
		randBytes(rb)
		var rh [32]byte
		for i, b := range rb {
			rh[i] = b
		}
	}

	var record auth.Record
	{
		record.SatelliteAddress = "sat.storj.test"

		randBytes(rb)
		record.MacaroonHead = make([]byte, 32)
		copy(record.MacaroonHead, rb)

		randBytes(rb)
		record.EncryptedSecretKey = make([]byte, 32)
		copy(record.EncryptedSecretKey, rb)

		randBytes(rb)
		record.EncryptedAccessGrant = make([]byte, 32)
		copy(record.EncryptedAccessGrant, rb)

		// Round to a second for avoiding  mismatches with monotonic clock
		// differences.
		expAt := time.Now().UTC().Round(time.Second)
		record.ExpiresAt = &expAt
		record.Public = true
	}

	require.NoError(t, kv.Put(ctx, keyHash, &record), "put")

	retrievedRecord, err := kv.Get(ctx, keyHash)
	require.NoError(t, err, "get")

	// Round to a second for avoiding  mismatches with monotonic clock
	// differences.
	retrievedExpAt := retrievedRecord.ExpiresAt.UTC().Round(time.Second)
	retrievedRecord.ExpiresAt = &retrievedExpAt
	require.Equal(t, record, *retrievedRecord)

	require.NoError(t, kv.Invalidate(ctx, keyHash, "invalidated for testing purpose"), "invalidate")
	_, err = kv.Get(ctx, keyHash)
	require.Error(t, err, "get-invalid")
	require.EqualError(t, err, auth.Invalid.New("%s", "invalidated for testing purpose").Error(), "get-invalid")

	require.NoError(t, kv.Delete(ctx, keyHash), "delete")
	retrievedRecord, err = kv.Get(ctx, keyHash)
	require.Nil(t, retrievedRecord, "get-after-deleted")
	require.NoError(t, err, "get-after-deleted")
}

func TestKV_CrdbAsOfSystemInterval(t *testing.T) {
	connStr := pgtest.PickCockroachAlt(t)

	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	kv, err := OpenTest(ctx, zap.NewNop(), t.Name(), connStr)
	require.NoError(t, err)
	defer func() { require.NoError(t, kv.Close()) }()

	require.NoError(t, kv.Ping(ctx), "ping")
	require.NoError(t, kv.MigrateToLatest(ctx), "migrateToLatest")

	randBytes := func(b []byte) {
		_, err := rand.Read(b)
		require.NoError(t, err, "randBytes")
	}
	rb := make([]byte, 32)

	var keyHash auth.KeyHash
	{
		randBytes(rb)
		var rh [32]byte
		for i, b := range rb {
			rh[i] = b
		}
	}

	var record auth.Record
	{
		record.SatelliteAddress = "sat.storj.test"

		randBytes(rb)
		record.MacaroonHead = make([]byte, 32)
		copy(record.MacaroonHead, rb)

		randBytes(rb)
		record.EncryptedSecretKey = make([]byte, 32)
		copy(record.EncryptedSecretKey, rb)

		randBytes(rb)
		record.EncryptedAccessGrant = make([]byte, 32)
		copy(record.EncryptedAccessGrant, rb)

		// Round to a second for avoiding  mismatches with monotonic clock
		// differences.
		expAt := time.Now().UTC().Round(time.Second)
		record.ExpiresAt = &expAt
		record.Public = true
	}

	require.NoError(t, kv.Put(ctx, keyHash, &record), "put")
	// Wait to make sure that query using 'AS OF SYSTEM TIME' clause is returning
	// the inserted record however we cannot ensure that it's actually such query
	// which is returning the error so, we use a delete and get in a row to ensure
	// it, see below.
	time.Sleep(10 * time.Millisecond)

	require.NoError(t, kv.Delete(ctx, keyHash), "delete")

	retrievedRecord, err := kv.GetWithNonDefaultAsOfInterval(
		ctx, keyHash, -10*time.Millisecond,
	)
	require.NoError(t, err, "get")

	// Make sure that the query using 'AS OF SYSTEM TIME' clause query is
	// returning results; if it wasn't the case then the returned record would be
	// nil.
	require.NotNil(t, retrievedRecord, "get")

	// Round to a second for avoiding  mismatches with monotonic clock
	// differences.
	retrievedExpAt := retrievedRecord.ExpiresAt.UTC().Round(time.Second)
	retrievedRecord.ExpiresAt = &retrievedExpAt
	require.Equal(t, record, *retrievedRecord)
}
