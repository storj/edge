// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package gcslock

import (
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/zeebo/errs"
	"go.uber.org/zap/zaptest"

	"storj.io/common/sync2"
	"storj.io/common/testcontext"
	"storj.io/gateway-mt/pkg/gcslock/gcsops"
	"storj.io/gateway-mt/pkg/internal/gcstest"
)

func TestMutex_PutHeadPatchDeleteCycle(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	mu := newMutex(ctx, t, gcstest.RandPathUTF8(1024), "")
	// 1st put should succeed & 2nd put should fail
	require.NoError(t, mu.put(ctx))
	require.ErrorIs(t, mu.put(ctx), gcsops.ErrPreconditionFailed)

	require.True(t, mu.shouldWait(ctx))

	require.NoError(t, mu.refresh(ctx))

	require.ErrorIs(t, mu.delete(ctx, "1"), gcsops.ErrPreconditionFailed)
	require.NoError(t, mu.delete(ctx, mu.lastKnownMetageneration))
}

func TestMutex_LockUnlock(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	mu := newMutex(ctx, t, gcstest.RandPathUTF8(1024), "")

	for i := 0; i < 3; i++ {
		require.NoError(t, mu.Lock(ctx))
		require.NoError(t, mu.Unlock(ctx))
	}

	t.Run("unlock of unlocked mutex", func(t *testing.T) {
		require.Error(t, mu.Unlock(ctx))
	})
}

func TestMutex_ConcurrentLockUnlock(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	name := gcstest.RandPathUTF8(1024)

	// Make sure we clean up after a failed test:
	defer func() {
		_ = newMutex(ctx, t, name, "11").Unlock(ctx)
	}()

	var observedLock uint32
	for i := 0; i < 10; i++ {
		i := i
		ctx.Go(func() error {
			mu := newMutex(ctx, t, name, strconv.Itoa(i))
			require.NoError(t, mu.Lock(ctx))
			require.True(t, atomic.CompareAndSwapUint32(&observedLock, 0, 1), "%d already locked", i)
			require.True(t, sync2.Sleep(ctx, 100*time.Millisecond))
			require.True(t, atomic.CompareAndSwapUint32(&observedLock, 1, 0))
			return mu.Unlock(ctx)
		})
	}
}

func newMutex(ctx *testcontext.Context, t *testing.T, name, tag string) *Mutex {
	jsonKey, bucket, err := gcstest.FindCredentials()
	if errs.Is(err, gcstest.ErrCredentialsNotFound) {
		t.Skipf("Skipping %s without credentials/bucket provided", t.Name())
	}

	logger := zaptest.NewLogger(t)
	defer ctx.Check(logger.Sync)

	if tag == "" {
		tag = "distributed lock"
	}

	m, err := NewMutex(ctx, Options{
		JSONKey: jsonKey,
		Name:    name,
		Bucket:  bucket,
		Logger:  logger.Named(tag).Sugar(),
	})
	require.NoError(t, err)

	return m
}
