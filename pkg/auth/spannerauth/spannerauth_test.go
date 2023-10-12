// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package spannerauth_test

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/memory"
	"storj.io/common/testcontext"
	"storj.io/common/testrand"
	"storj.io/gateway-mt/pkg/auth/authdb"
	"storj.io/gateway-mt/pkg/auth/spannerauth"
	"storj.io/gateway-mt/pkg/auth/spannerauth/internal/spannerauthtest"
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

	db, err := spannerauth.OpenWithEmulatorAddr(ctx, logger, server.Addr, "", "projects/P/instances/I/databases/D")
	require.NoError(t, err)
	defer ctx.Check(db.Close)

	require.NoError(t, db.HealthCheck(ctx))

	reference := make(map[authdb.KeyHash]*authdb.Record)
	// permanent
	for i := 0; i < 123; i++ {
		var k authdb.KeyHash
		require.NoError(t, k.SetBytes([]byte(strconv.Itoa(i))))
		r := createRandomRecord(time.Time{})
		reference[k] = r
		require.NoError(t, db.Put(ctx, k, r))
	}
	// already expired
	for i := 123; i < 456; i++ {
		var k authdb.KeyHash
		require.NoError(t, k.SetBytes([]byte(strconv.Itoa(i))))
		r := createRandomRecord(time.Now())
		reference[k] = r
		require.NoError(t, db.Put(ctx, k, r))
	}
	// expiring, but in a long time
	for i := 456; i < 789; i++ {
		var k authdb.KeyHash
		require.NoError(t, k.SetBytes([]byte(strconv.Itoa(i))))
		r := createRandomRecord(time.Now().Add(time.Hour).UTC())
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

func createRandomRecord(expiresAt time.Time) *authdb.Record {
	k := testrand.Key()
	r := authdb.Record{
		SatelliteAddress:     testrand.NodeID().String(),
		MacaroonHead:         testrand.Bytes(32 * memory.B),
		EncryptedSecretKey:   k[:],
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
