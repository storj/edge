// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package spannerauth_test

import (
	"crypto/rand"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/encryption"
	"storj.io/common/memory"
	"storj.io/common/storj"
	"storj.io/common/testcontext"
	"storj.io/common/testrand"
	"storj.io/edge/pkg/auth/authdb"
	"storj.io/edge/pkg/auth/spannerauth"
	"storj.io/edge/pkg/auth/spannerauth/internal/spannerauthtest"
)

// NOTE(artur): I'm hoping to extract this test to be a general test in the
// authdb package for all available backends.
func TestCloudDatabase(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	logger := zaptest.NewLogger(t)
	defer ctx.Check(logger.Sync)

	server, err := spannerauthtest.ConfigureTestServer(ctx, logger)
	require.NoError(t, err)
	defer server.Close()

	db, err := spannerauth.Open(ctx, logger, spannerauth.Config{
		DatabaseName: "projects/P/instances/I/databases/D",
		Address:      server.Addr,
	})
	require.NoError(t, err)
	defer ctx.Check(db.Close)

	require.NoError(t, db.HealthCheck(ctx))

	reference := make(map[authdb.KeyHash]*authdb.Record)
	// permanent
	for i := 0; i < 123; i++ {
		var k authdb.KeyHash
		require.NoError(t, k.SetBytes([]byte(strconv.Itoa(i))))
		r := createRandomRecord(t, time.Time{})
		reference[k] = r
		require.NoError(t, db.Put(ctx, k, r))
	}
	// already expired
	for i := 123; i < 456; i++ {
		var k authdb.KeyHash
		require.NoError(t, k.SetBytes([]byte(strconv.Itoa(i))))
		r := createRandomRecord(t, time.Now())
		reference[k] = r
		require.NoError(t, db.Put(ctx, k, r))
	}
	// expiring, but in a long time
	for i := 456; i < 789; i++ {
		var k authdb.KeyHash
		require.NoError(t, k.SetBytes([]byte(strconv.Itoa(i))))
		r := createRandomRecord(t, time.Now().Add(time.Hour).UTC())
		reference[k] = r
		require.NoError(t, db.Put(ctx, k, r))
	}

	for k, r := range reference {
		actual, err := db.Get(ctx, k)
		require.NoError(t, err)
		if r.ExpiresAt != nil && r.ExpiresAt.Before(time.Now()) {
			require.Nil(t, actual)
		} else {
			require.Equal(t, r, actual)
		}
	}
}

func TestRecordExpiry(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	logger := zaptest.NewLogger(t)
	defer ctx.Check(logger.Sync)

	server, err := spannerauthtest.ConfigureTestServer(ctx, logger)
	require.NoError(t, err)
	defer server.Close()

	db, err := spannerauth.Open(ctx, logger, spannerauth.Config{
		DatabaseName: "projects/P/instances/I/databases/D",
		Address:      server.Addr,
	})
	require.NoError(t, err)
	defer ctx.Check(db.Close)

	require.NoError(t, db.HealthCheck(ctx))

	var k1 authdb.KeyHash
	require.NoError(t, k1.SetBytes([]byte(strconv.Itoa(1))))

	futureTime := time.Now().Add(time.Hour).UTC()
	r1 := createRandomRecord(t, futureTime)
	require.NoError(t, err, db.Put(ctx, k1, r1))

	r, err := db.Get(ctx, k1)
	require.NoError(t, err)
	require.Equal(t, &futureTime, r.ExpiresAt)

	var k2 authdb.KeyHash
	require.NoError(t, k2.SetBytes([]byte(strconv.Itoa(2))))

	r2 := createRandomRecord(t, time.Time{})
	// createRandomRecord will discard out any zero time, so ensure it's set.
	r2.ExpiresAt = &time.Time{}
	require.NoError(t, err, db.Put(ctx, k2, r2))

	r, err = db.Get(ctx, k2)
	require.NoError(t, err)
	require.Nil(t, r.ExpiresAt)
}

func createRandomRecord(t *testing.T, expiresAt time.Time) *authdb.Record {
	var secretKey authdb.SecretKey
	_, err := rand.Read(secretKey[:])
	require.NoError(t, err)

	encKey, err := authdb.NewEncryptionKey()
	require.NoError(t, err)

	storjKey := encKey.ToStorjKey()

	encSecretKey, err := encryption.Encrypt(secretKey[:], storj.EncAESGCM, &storjKey, &storj.Nonce{})
	require.NoError(t, err)

	r := authdb.Record{
		SatelliteAddress:     testrand.NodeID().String(),
		MacaroonHead:         testrand.Bytes(32 * memory.B),
		EncryptedSecretKey:   encSecretKey,
		EncryptedAccessGrant: testrand.Bytes(4 * memory.KiB),
	}
	if !expiresAt.IsZero() {
		r.ExpiresAt = &expiresAt
	}
	if testrand.Intn(2) == 1 {
		r.Public = true
	}
	return &r
}
