// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package memauth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"storj.io/common/testcontext"
	"storj.io/common/testrand"
	"storj.io/gateway-mt/pkg/auth/authdb"
)

func TestKV(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	kv := New()
	defer func() { require.NoError(t, kv.Close()) }()

	r1 := &authdb.Record{SatelliteAddress: "abc", MacaroonHead: []byte{255}}
	r2 := &authdb.Record{SatelliteAddress: "def", MacaroonHead: []byte{254}}

	for i := 0; i < 100; i++ {
		if i%2 == 0 {
			require.NoError(t, kv.Put(ctx, authdb.KeyHash{byte(i)}, r1))
		} else {
			require.NoError(t, kv.Put(ctx, authdb.KeyHash{byte(i)}, r2))
		}
	}

	for i := 0; i < 100; i++ {
		v, err := kv.Get(ctx, authdb.KeyHash{byte(i)})
		require.NoError(t, err)
		if i%2 == 0 {
			assert.Equal(t, r1, v)
		} else {
			assert.Equal(t, r2, v)
		}
	}

	require.Error(t, kv.Put(ctx, authdb.KeyHash{42}, nil))

	require.NoError(t, kv.PingDB(ctx))

	for i := 0; i < 100; i += 2 {
		oneSecondAgo := time.Now().Add(-1 * time.Second)
		kv.entries[authdb.KeyHash{byte(i)}].ExpiresAt = &oneSecondAgo
	}

	maxTime := time.Unix(1<<62, 0)

	r3 := &authdb.Record{SatelliteAddress: "ghi", ExpiresAt: &maxTime}

	require.NoError(t, kv.Put(ctx, authdb.KeyHash{byte(253)}, r3))

	// Confirm DeleteUnused is idempotent and deletes only expired records.
	for i := 0; i < 10; i++ {
		count, rounds, heads, err := kv.DeleteUnused(ctx, 0, 0, 0)
		require.NoError(t, err)

		if i == 0 {
			assert.Equal(t, int64(50), count)
			assert.Equal(t, int64(1), rounds)
			assert.Equal(t, map[string]int64{string([]byte{255}): 50}, heads)
		} else {
			assert.Equal(t, int64(0), count)
			assert.Equal(t, int64(1), rounds)
			assert.Equal(t, make(map[string]int64), heads)
		}
	}

	for i := 0; i < 100; i++ {
		v, err := kv.Get(ctx, authdb.KeyHash{byte(i)})
		require.NoError(t, err)
		if i%2 == 0 {
			assert.Nil(t, v)
		} else {
			assert.Equal(t, r2, v)
		}
	}

	{
		v, err := kv.Get(ctx, authdb.KeyHash{byte(253)})
		require.NoError(t, err)
		assert.Equal(t, r3, v)
	}
}

// TestKVParallel is mainly to check for any race conditions.
func TestKVParallel(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	kv := New()

	ctx.Go(func() error { // Put
		for i := 0; i < 10000; i++ {
			_ = kv.Put(ctx, authdb.KeyHash{byte(testrand.Intn(100))}, nil)
		}
		return nil
	})

	ctx.Go(func() error { // Get
		for i := 0; i < 10000; i++ {
			_, _ = kv.Get(ctx, authdb.KeyHash{byte(testrand.Intn(100))})
		}
		return nil
	})

	ctx.Go(func() error { // DeleteUnused
		for i := 0; i < 10000; i++ {
			if _, _, _, err := kv.DeleteUnused(ctx, 0, 0, 0); err != nil {
				return err
			}
		}
		return nil
	})

	ctx.Go(func() error { // Ping
		for i := 0; i < 10000; i++ {
			if err := kv.PingDB(ctx); err != nil {
				return err
			}
		}
		return nil
	})

	ctx.Wait()
}
