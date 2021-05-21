// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package sqlauth

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"storj.io/common/testcontext"
	"storj.io/gateway-mt/auth"
	"storj.io/private/dbutil/pgtest"
)

func TestKVPostgres(t *testing.T)  { testKV(t, pgtest.PickPostgres(t)) }
func TestKVCockroach(t *testing.T) { testKV(t, pgtest.PickCockroachAlt(t)) }

func testKV(t *testing.T, connStr string) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	db, err := OpenUnique(ctx, connStr, "kv-test")
	require.NoError(t, err)
	defer func() { require.NoError(t, db.Close()) }()
	kv := &KV{db: db}

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

		record.Public = true
	}

	require.NoError(t, kv.Put(ctx, keyHash, &record), "put")

	retrievedRecord, err := kv.Get(ctx, keyHash)
	require.NoError(t, err, "get")
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
