// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package memauth

import (
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"storj.io/common/testcontext"
	"storj.io/gateway-mt/auth/store"
)

func TestKV(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	kv := New()

	r1 := &store.Record{SatelliteAddress: "abc"}
	r2 := &store.Record{SatelliteAddress: "def"}

	for i := 0; i < 100; i++ {
		if i%2 == 0 {
			require.NoError(t, kv.Put(ctx, store.KeyHash{byte(i)}, r1))
		} else {
			require.NoError(t, kv.Put(ctx, store.KeyHash{byte(i)}, r2))
		}
	}

	require.NoError(t, kv.Invalidate(ctx, store.KeyHash{10}, ""))
	require.NoError(t, kv.Invalidate(ctx, store.KeyHash{11}, ""))
	require.NoError(t, kv.Invalidate(ctx, store.KeyHash{12}, ""))
	require.NoError(t, kv.Invalidate(ctx, store.KeyHash{12}, ""))

	require.NoError(t, kv.Delete(ctx, store.KeyHash{43}))
	require.NoError(t, kv.Delete(ctx, store.KeyHash{11}))
	require.NoError(t, kv.Delete(ctx, store.KeyHash{99}))
	require.NoError(t, kv.Delete(ctx, store.KeyHash{99}))

	for i := 0; i < 100; i++ {
		v, err := kv.Get(ctx, store.KeyHash{byte(i)})

		switch i {
		case 11, 43, 99:
			require.NoError(t, err)
		case 10, 12:
			require.Error(t, err)
		default:
			require.NoError(t, err)
			if i%2 == 0 {
				assert.Equal(t, r1, v)
			} else {
				assert.Equal(t, r2, v)
			}
		}
	}

	require.Error(t, kv.Put(ctx, store.KeyHash{42}, nil))

	require.NoError(t, kv.Ping(ctx))
}

// TestKVParallel is mainly to check for any race conditions.
func TestKVParallel(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	kv := New()

	ctx.Go(func() error { // Put
		r := rand.New(rand.NewSource(time.Now().UnixNano()))

		for i := 0; i < 10000; i++ {
			_ = kv.Put(ctx, store.KeyHash{byte(r.Intn(100))}, nil)
		}

		return nil
	})

	ctx.Go(func() error { // Get
		r := rand.New(rand.NewSource(time.Now().UnixNano()))

		for i := 0; i < 10000; i++ {
			_, _ = kv.Get(ctx, store.KeyHash{byte(r.Intn(100))})
		}

		return nil
	})

	ctx.Go(func() error { // Delete
		r := rand.New(rand.NewSource(time.Now().UnixNano()))

		for i := 0; i < 10000; i++ {
			if err := kv.Delete(ctx, store.KeyHash{byte(r.Intn(100))}); err != nil {
				return err
			}
		}

		return nil
	})

	ctx.Go(func() error { // Invalidate
		r := rand.New(rand.NewSource(time.Now().UnixNano()))

		for i := 0; i < 10000; i++ {
			if err := kv.Invalidate(ctx, store.KeyHash{byte(r.Intn(100))}, ""); err != nil {
				return err
			}
		}

		return nil
	})

	ctx.Go(func() error { // Ping
		for i := 0; i < 10000; i++ {
			if err := kv.Ping(ctx); err != nil {
				return err
			}
		}

		return nil
	})

	ctx.Wait()
}
