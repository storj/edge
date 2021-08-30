// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package main_test

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"storj.io/common/testcontext"
	"storj.io/gateway-mt/auth/authdb"
	"storj.io/gateway-mt/auth/sqlauth"
	cmd "storj.io/gateway-mt/cmd/authservice-unused-records"
	"storj.io/private/dbutil"
	"storj.io/private/dbutil/pgtest"
)

func TestVerifyFlags(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		config  cmd.Config
		wantErr bool
	}{
		{
			config:  cmd.Config{},
			wantErr: true,
		},
		{
			config: cmd.Config{
				AuthServiceDB:      "",
				AsOfSystemInterval: 0,
				MacaroonHead:       make([]byte, 0),
				SelectSize:         0,
				DeleteSize:         5001,
				DryRun:             false,
			},
			wantErr: true,
		},
		{
			config: cmd.Config{
				AuthServiceDB:      "test",
				AsOfSystemInterval: -5 * time.Second,
				MacaroonHead:       []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 100, 255},
				SelectSize:         12345,
				DeleteSize:         1234,
				DryRun:             true,
			},
			wantErr: false,
		},
	} {
		assert.Equal(t, tt.wantErr, tt.config.VerifyFlags() != nil)
	}
}

func TestDelete_Postgres(t *testing.T) {
	t.Parallel()
	testDelete(t, pgtest.PickPostgres(t), 0)
}

func TestDelete_Cockroach(t *testing.T) {
	t.Parallel()
	testDelete(t, pgtest.PickCockroachAlt(t), time.Microsecond)
}

func testDelete(t *testing.T, connstr string, wait time.Duration) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	kv, err := sqlauth.OpenTest(ctx, zap.NewNop(), t.Name(), connstr)
	require.NoError(t, err)
	defer func() { require.NoError(t, kv.Close()) }()

	require.NoError(t, kv.Ping(ctx))
	require.NoError(t, kv.MigrateToLatest(ctx))

	config := cmd.Config{
		AuthServiceDB:      connstr,
		AsOfSystemInterval: -wait,
		MacaroonHead:       []byte{1, 3, 3, 7},
		SelectSize:         20,
		DeleteSize:         5,
		DryRun:             true,
	}

	n := time.Now().Round(time.Second)

	r0 := &authdb.Record{
		SatelliteAddress:     "abc",
		MacaroonHead:         []byte{0},
		EncryptedSecretKey:   []byte{1},
		EncryptedAccessGrant: []byte{2},
	}
	r1 := &authdb.Record{
		SatelliteAddress:     "def",
		MacaroonHead:         config.MacaroonHead,
		EncryptedSecretKey:   []byte{1},
		EncryptedAccessGrant: []byte{2},
	}
	r2 := &authdb.Record{
		SatelliteAddress:     "ghi",
		MacaroonHead:         config.MacaroonHead,
		EncryptedSecretKey:   []byte{1},
		EncryptedAccessGrant: []byte{2},
		ExpiresAt:            &n,
	}

	const iterations = 1000

	for i := 0; i < iterations; i++ {
		switch i % 3 {
		case 0:
			require.NoError(t, kv.Put(ctx, itob32(i), r0))
		case 1:
			require.NoError(t, kv.Put(ctx, itob32(i), r1))
		case 2:
			require.NoError(t, kv.Put(ctx, itob32(i), r2))
		}
	}

	time.Sleep(wait)

	db, impl := kv.TagSQL(), dbutil.ImplementationForScheme(kv.Schema())
	wouldDelete, count, rounds, err := cmd.Delete(ctx, zap.NewNop(), db, impl, config)

	require.NoError(t, err)
	assert.Equal(t, 333, wouldDelete)
	assert.Equal(t, int64(0), count)
	assert.Equal(t, int64(0), rounds)

	// Confirm `--dry-run` does not delete any data:

	time.Sleep(wait)

	for i := 0; i < iterations; i++ {
		switch i % 3 {
		case 0:
			r, err := kv.GetWithNonDefaultAsOfInterval(ctx, itob32(i), -wait)
			require.NoError(t, err)
			assert.Equal(t, r0, r)
		case 1:
			r, err := kv.GetWithNonDefaultAsOfInterval(ctx, itob32(i), -wait)
			require.NoError(t, err)
			assert.Equal(t, r1, r)
		case 2:
			r, err := kv.GetWithNonDefaultAsOfInterval(ctx, itob32(i), -wait)
			require.NoError(t, err)
			assert.Equal(t, r2, r)
		}
	}

	// Perform deletion:

	config.DryRun = false

	wouldDelete, count, rounds, err = cmd.Delete(ctx, zap.NewNop(), db, impl, config)

	require.NoError(t, err)
	assert.Equal(t, 333, wouldDelete)
	assert.Equal(t, int64(333), count)
	assert.Equal(t, int64(67), rounds)

	// Confirm deletion deleted only relevant data:

	time.Sleep(wait)

	for i := 0; i < iterations; i++ {
		switch i % 3 {
		case 0:
			r, err := kv.GetWithNonDefaultAsOfInterval(ctx, itob32(i), -wait)
			require.NoError(t, err)
			assert.Equal(t, r0, r)
		case 1:
			r, err := kv.GetWithNonDefaultAsOfInterval(ctx, itob32(i), -wait)
			require.NoError(t, err)
			assert.Nil(t, r)
		case 2:
			r, err := kv.GetWithNonDefaultAsOfInterval(ctx, itob32(i), -wait)
			require.NoError(t, err)
			assert.Equal(t, r2, r)
		}
	}
}

func itob32(i int) [32]byte {
	var k [32]byte

	for j, r := range strconv.Itoa(i) {
		if j > 31 {
			panic("out of range")
		}
		k[j] = byte(r)
	}

	return k
}
