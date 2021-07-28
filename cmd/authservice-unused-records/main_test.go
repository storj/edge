// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package main_test

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"storj.io/common/testcontext"
	"storj.io/gateway-mt/auth"
	"storj.io/gateway-mt/auth/sqlauth"
	cmd "storj.io/gateway-mt/cmd/authservice-unused-records"
	"storj.io/private/dbutil"
	"storj.io/private/dbutil/pgtest"
	"storj.io/private/dbutil/tempdb"
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
	testDelete(t, pgtest.PickCockroachAlt(t), 100*time.Millisecond)
}

func testDelete(t *testing.T, connstr string, wait time.Duration) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	kv, err := openTest(ctx, zap.NewNop(), t.Name(), connstr)
	require.NoError(t, err)
	defer func() { require.NoError(t, kv.Close()) }()

	require.NoError(t, kv.Ping(ctx))
	require.NoError(t, kv.MigrateToLatest(ctx))

	config := cmd.Config{
		AuthServiceDB:      connstr,
		AsOfSystemInterval: -wait,
		MacaroonHead:       []byte{1, 3, 3, 7},
		SelectSize:         200,
		DeleteSize:         50,
		DryRun:             true,
	}

	n := time.Now().Round(time.Second)

	r0 := &auth.Record{
		SatelliteAddress:     "abc",
		MacaroonHead:         []byte{0},
		EncryptedSecretKey:   []byte{1},
		EncryptedAccessGrant: []byte{2},
	}
	r1 := &auth.Record{
		SatelliteAddress:     "def",
		MacaroonHead:         config.MacaroonHead,
		EncryptedSecretKey:   []byte{1},
		EncryptedAccessGrant: []byte{2},
	}
	r2 := &auth.Record{
		SatelliteAddress:     "ghi",
		MacaroonHead:         config.MacaroonHead,
		EncryptedSecretKey:   []byte{1},
		EncryptedAccessGrant: []byte{2},
		ExpiresAt:            &n,
	}

	const iterations = 10000

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

	db, impl := kv.TestingTagSQL(), dbutil.ImplementationForScheme(kv.TestingSchema())
	wouldDelete, count, rounds, err := cmd.Delete(ctx, zap.NewNop(), db, impl, config)

	require.NoError(t, err)
	assert.Equal(t, 3333, wouldDelete)
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
	assert.Equal(t, 3333, wouldDelete)
	assert.Equal(t, int64(3333), count)
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

func openTest(ctx context.Context, log *zap.Logger, name, connstr string) (*sqlauth.KV, error) {
	tempDB, err := tempdb.OpenUnique(ctx, connstr, name)
	if err != nil {
		return nil, err
	}

	opts := sqlauth.Options{
		ApplicationName: "authservice-unused-records_test",
	}

	kv, err := sqlauth.Open(ctx, log, tempDB.ConnStr, opts)
	if err != nil {
		return nil, err
	}

	kv.TestingSetCleanup(tempDB.Close)

	return kv, nil
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
