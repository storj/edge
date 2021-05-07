// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package memauth

import (
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"storj.io/common/testcontext"
	"storj.io/gateway-mt/auth"
)

func TestKV(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	kv := New()

	r1 := &auth.Record{SatelliteAddress: "abc"}
	r2 := &auth.Record{SatelliteAddress: "def"}

	for i := 0; i < 100; i++ {
		if i%2 == 0 {
			require.NoError(t, kv.Put(ctx, auth.KeyHash{byte(i)}, r1))
		} else {
			require.NoError(t, kv.Put(ctx, auth.KeyHash{byte(i)}, r2))
		}
	}

	require.NoError(t, kv.Invalidate(ctx, auth.KeyHash{10}, ""))
	require.NoError(t, kv.Invalidate(ctx, auth.KeyHash{11}, ""))
	require.NoError(t, kv.Invalidate(ctx, auth.KeyHash{12}, ""))
	require.NoError(t, kv.Invalidate(ctx, auth.KeyHash{12}, ""))

	require.NoError(t, kv.Delete(ctx, auth.KeyHash{43}))
	require.NoError(t, kv.Delete(ctx, auth.KeyHash{11}))
	require.NoError(t, kv.Delete(ctx, auth.KeyHash{99}))
	require.NoError(t, kv.Delete(ctx, auth.KeyHash{99}))

	for i := 0; i < 100; i++ {
		v, err := kv.Get(ctx, auth.KeyHash{byte(i)})

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

	require.Error(t, kv.Put(ctx, auth.KeyHash{42}, nil))

	require.NoError(t, kv.Ping(ctx))
}

// TestKVParallel is mainly to check for any race conditions.
func TestKVParallel(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	kv := New()

	var (
		end   sync.WaitGroup // to coordinate when finished
		start sync.WaitGroup // to coordinate when to start
	)

	end.Add(5)
	start.Add(5)

	go func() { // Put
		defer end.Done()

		r := rand.New(rand.NewSource(time.Now().UnixNano()))

		start.Done()
		start.Wait()

		for i := 0; i < 10000; i++ {
			_ = kv.Put(ctx, auth.KeyHash{byte(r.Intn(100))}, nil)
		}
	}()

	go func() { // Get
		defer end.Done()

		r := rand.New(rand.NewSource(time.Now().UnixNano()))

		start.Done()
		start.Wait()

		for i := 0; i < 10000; i++ {
			_, _ = kv.Get(ctx, auth.KeyHash{byte(r.Intn(100))})
		}
	}()

	go func() { // Delete
		defer end.Done()

		r := rand.New(rand.NewSource(time.Now().UnixNano()))

		start.Done()
		start.Wait()

		for i := 0; i < 10000; i++ {
			require.NoError(t, kv.Delete(ctx, auth.KeyHash{byte(r.Intn(100))}))
		}
	}()

	go func() { // Invalidate
		defer end.Done()

		r := rand.New(rand.NewSource(time.Now().UnixNano()))

		start.Done()
		start.Wait()

		for i := 0; i < 10000; i++ {
			require.NoError(t, kv.Invalidate(ctx, auth.KeyHash{byte(r.Intn(100))}, ""))
		}
	}()

	go func() { // Ping
		defer end.Done()
		start.Done()
		start.Wait()

		for i := 0; i < 10000; i++ {
			require.NoError(t, kv.Ping(ctx))
		}
	}()

	end.Wait()
}
