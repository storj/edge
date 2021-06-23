// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package sqlauth_test

import (
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"storj.io/common/testcontext"
	"storj.io/gateway-mt/auth/authdb"
	"storj.io/private/dbutil/pgtest"
)

func TestKVFullCycle_Postgres(t *testing.T) {
	t.Parallel()
	testKVFullCycle(t, pgtest.PickPostgres(t))
}
func TestKVFullCycle_Cockroach(t *testing.T) {
	t.Parallel()
	testKVFullCycle(t, pgtest.PickCockroachAlt(t))
}

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

	var keyHash authdb.KeyHash
	{
		randBytes(rb)
		var rh [32]byte
		for i, b := range rb {
			rh[i] = b
		}
	}

	var record authdb.Record
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
	require.EqualError(t, err, authdb.Invalid.New("%s", "invalidated for testing purpose").Error(), "get-invalid")

	require.NoError(t, kv.Delete(ctx, keyHash), "delete")
	retrievedRecord, err = kv.Get(ctx, keyHash)
	require.Nil(t, retrievedRecord, "get-after-deleted")
	require.NoError(t, err, "get-after-deleted")
}

func TestKV_CrdbAsOfSystemInterval(t *testing.T) {
	t.Parallel()

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

	var keyHash authdb.KeyHash
	{
		randBytes(rb)
		var rh [32]byte
		for i, b := range rb {
			rh[i] = b
		}
	}

	var record authdb.Record
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
	time.Sleep(200 * time.Millisecond)

	require.NoError(t, kv.Delete(ctx, keyHash), "delete")

	// NOTE: The below query associated with GetWithNonDefaultAsOfInterval
	// assumes that the previous Delete query took less than 100ms. This might
	// not always be true (TODO?), but the chances of this happening are tiny.
	retrievedRecord, err := kv.GetWithNonDefaultAsOfInterval(ctx, keyHash, -100*time.Millisecond)
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

func TestKV_DeleteUnused_Postgres(t *testing.T) {
	t.Parallel()
	testKVDeleteUnused(t, pgtest.PickPostgres(t), 0)
}

func TestKV_DeleteUnused_Cockroach(t *testing.T) {
	t.Parallel()
	testKVDeleteUnused(t, pgtest.PickCockroachAlt(t), time.Microsecond)
}

func testKVDeleteUnused(t *testing.T, connstr string, wait time.Duration) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	kv, err := OpenTest(ctx, zap.NewNop(), t.Name(), connstr)
	require.NoError(t, err)
	defer func() { require.NoError(t, kv.Close()) }()

	require.NoError(t, kv.Ping(ctx))
	require.NoError(t, kv.MigrateToLatest(ctx))

	r1 := &authdb.Record{
		SatelliteAddress:     "abc",
		MacaroonHead:         []byte{0},
		EncryptedSecretKey:   []byte{1},
		EncryptedAccessGrant: []byte{2},
	}

	for i := 0; i < 100; i += 2 {
		require.NoError(t, kv.Put(ctx, authdb.KeyHash{byte(i)}, r1))
	}

	time.Sleep(wait)

	// Confirm DeleteUnused is idempotent.
	for i := 0; i < 3; i++ {
		count, rounds, err := kv.DeleteUnused(ctx, wait, 20, 5)
		require.NoError(t, err)
		assert.Equal(t, int64(0), count)
		assert.Equal(t, int64(0), rounds)
	}

	time.Sleep(wait)

	for i := 0; i < 100; i++ {
		r, err := kv.GetWithNonDefaultAsOfInterval(ctx, authdb.KeyHash{byte(i)}, -wait)
		require.NoError(t, err)
		if i%2 == 0 {
			assert.Equal(t, r1, r)
		} else {
			assert.Nil(t, r)
		}
	}

	for i := 1; i < 100; i += 2 {
		n := time.Now()
		r := &authdb.Record{
			SatelliteAddress:     "def",
			MacaroonHead:         []byte{3},
			EncryptedSecretKey:   []byte{4},
			EncryptedAccessGrant: []byte{5},
			ExpiresAt:            &n,
		}
		require.NoError(t, kv.Put(ctx, authdb.KeyHash{byte(i)}, r))
	}

	for i := 50; i < 100; i += 2 {
		require.NoError(t, kv.Invalidate(ctx, authdb.KeyHash{byte(i)}, "test"))
	}

	maxTime := time.Unix(1<<43, 0)

	r2 := &authdb.Record{
		SatelliteAddress:     "ghi",
		MacaroonHead:         []byte{6},
		EncryptedSecretKey:   []byte{7},
		EncryptedAccessGrant: []byte{8},
		ExpiresAt:            &maxTime,
	}

	require.NoError(t, kv.Put(ctx, authdb.KeyHash{byte(255)}, r2))

	time.Sleep(wait)

	// Confirm DeleteUnused is idempotent and deletes only expired/invalid
	// records.
	for i := 0; i < 5; i++ {
		count, rounds, err := kv.DeleteUnused(ctx, wait, 20, 5)
		require.NoError(t, err)

		if i == 0 {
			assert.Equal(t, int64(75), count)
			assert.Equal(t, int64(15), rounds)
		} else {
			assert.Equal(t, int64(0), count)
			assert.Equal(t, int64(0), rounds)
		}
	}

	time.Sleep(wait)

	for i := 0; i < 100; i++ {
		r, err := kv.GetWithNonDefaultAsOfInterval(ctx, authdb.KeyHash{byte(i)}, -wait)
		require.NoError(t, err)
		if i < 50 && i%2 == 0 {
			assert.Equal(t, r1, r)
		} else {
			assert.Nil(t, r)
		}
	}

	{
		r, err := kv.GetWithNonDefaultAsOfInterval(ctx, authdb.KeyHash{byte(255)}, -wait)
		require.NoError(t, err)
		assert.Equal(t, r2, r)
	}
}

func TestKV_DeleteUnusedBatching_Postgres(t *testing.T) {
	t.Parallel()
	t.Run("10/5", func(t *testing.T) {
		t.Parallel()
		testKVDeleteUnusedBatching(t, pgtest.PickPostgres(t), 10, 5, 100, 20, 0)
	})
	t.Run("1000/250", func(t *testing.T) {
		t.Parallel()
		testKVDeleteUnusedBatching(t, pgtest.PickPostgres(t), 1000, 250, 3214, 13, 0)
	})
	t.Run("1111/321", func(t *testing.T) {
		t.Parallel()
		testKVDeleteUnusedBatching(t, pgtest.PickPostgres(t), 1111, 321, 5000, 18, 0)
	})
}

func TestKV_DeleteUnusedBatching_Cockroach(t *testing.T) {
	t.Parallel()
	t.Run("10/5", func(t *testing.T) {
		t.Parallel()
		testKVDeleteUnusedBatching(t, pgtest.PickCockroachAlt(t), 10, 5, 100, 20, time.Second)
	})
	t.Run("1000/250", func(t *testing.T) {
		t.Parallel()
		testKVDeleteUnusedBatching(t, pgtest.PickCockroachAlt(t), 1000, 250, 3214, 13, time.Second)
	})
	t.Run("1111/321", func(t *testing.T) {
		t.Parallel()
		testKVDeleteUnusedBatching(t, pgtest.PickCockroachAlt(t), 1111, 321, 5000, 18, time.Second)
	})
}

func testKVDeleteUnusedBatching(t *testing.T, connstr string, selectSize, deleteSize int, expectedCount, expectedRounds int64, wait time.Duration) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	kv, err := OpenTest(ctx, zap.NewNop(), t.Name(), connstr)
	require.NoError(t, err)
	defer func() { require.NoError(t, kv.Close()) }()

	require.NoError(t, kv.Ping(ctx))
	require.NoError(t, kv.MigrateToLatest(ctx))

	for i := int64(0); i < expectedCount; i++ {
		n := time.Now()
		r := &authdb.Record{
			SatelliteAddress:     "abc",
			MacaroonHead:         []byte{0},
			EncryptedSecretKey:   []byte{1},
			EncryptedAccessGrant: []byte{2},
			ExpiresAt:            &n,
		}

		var k [32]byte

		for j, r := range strconv.FormatInt(i, 16) {
			k[j] = byte(r)
		}

		require.NoError(t, kv.Put(ctx, k, r))
	}

	time.Sleep(wait)

	count, rounds, err := kv.DeleteUnused(ctx, wait, selectSize, deleteSize)
	require.NoError(t, err)
	assert.Equal(t, expectedCount, count)
	assert.Equal(t, expectedRounds, rounds)
}
