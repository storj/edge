// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package s3lock

import (
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/sync2"
	"storj.io/common/testcontext"
	"storj.io/edge/pkg/internal/s3test"
)

func TestMutex_PutHeadRefreshDeleteCycle(t *testing.T) {
	cfg, err := s3test.FindCredentials()
	if s3test.ErrCredentialsNotFound.Has(err) {
		t.Skipf("Skipping %s without credentials/bucket provided", t.Name())
	}

	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	mu := newMutex(ctx, t, cfg, s3test.RandPathUTF8(1024), "")
	// 1st put should succeed & 2nd put should fail (object already exists).
	require.NoError(t, mu.put(ctx))
	require.ErrorIs(t, mu.put(ctx), ErrPreconditionFailed)

	// The lock is not expired, so we should wait.
	require.True(t, mu.shouldWait(ctx))

	require.NoError(t, mu.refresh(ctx))

	// Deleting with a stale/wrong ETag must fail the precondition; deleting with
	// the current ETag must succeed.
	require.ErrorIs(t, mu.delete(ctx, `"00000000000000000000000000000000"`), ErrPreconditionFailed)
	require.NoError(t, mu.delete(ctx, mu.lastKnownETag))
}

func TestMutex_LockUnlock(t *testing.T) {
	cfg, err := s3test.FindCredentials()
	if s3test.ErrCredentialsNotFound.Has(err) {
		t.Skipf("Skipping %s without credentials/bucket provided", t.Name())
	}

	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	mu := newMutex(ctx, t, cfg, s3test.RandPathUTF8(1024), "")

	for range 3 {
		require.NoError(t, mu.Lock(ctx))
		require.NoError(t, mu.Unlock(ctx))
	}

	// Unlike gcslock, S3 Unlock is idempotent: releasing an already-released
	// lock is not an error (a conditional delete of a missing object returns
	// 412, which we treat as "already released").
	t.Run("unlock of unlocked mutex is idempotent", func(t *testing.T) {
		require.NoError(t, mu.Unlock(ctx))
	})
}

func TestMutex_ConcurrentLockUnlock(t *testing.T) {
	cfg, err := s3test.FindCredentials()
	if s3test.ErrCredentialsNotFound.Has(err) {
		t.Skipf("Skipping %s without credentials/bucket provided", t.Name())
	}

	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	name := s3test.RandPathUTF8(1024)

	// Make sure we clean up any leftover lock object after a failed test.
	defer func() {
		client, err := cfg.Client(ctx)
		require.NoError(t, err)
		_, _ = client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(cfg.Bucket),
			Key:    aws.String(name),
		})
	}()

	var observedLock uint32
	for i := range 10 {
		i := i
		ctx.Go(func() error {
			mu := newMutex(ctx, t, cfg, name, strconv.Itoa(i))
			require.NoError(t, mu.Lock(ctx))
			require.True(t, atomic.CompareAndSwapUint32(&observedLock, 0, 1), "%d already locked", i)
			require.True(t, sync2.Sleep(ctx, 100*time.Millisecond))
			require.True(t, atomic.CompareAndSwapUint32(&observedLock, 1, 0))
			return mu.Unlock(ctx)
		})
	}
}

func newMutex(ctx *testcontext.Context, t *testing.T, cfg s3test.Config, name, tag string) *Mutex {
	logger := zaptest.NewLogger(t)
	defer ctx.Check(logger.Sync)

	if tag == "" {
		tag = "distributed lock"
	}

	client, err := cfg.Client(ctx)
	require.NoError(t, err)

	m, err := NewMutex(ctx, Options{
		Client: client,
		Name:   name,
		Bucket: cfg.Bucket,
		Logger: logger.Named(tag).Sugar(),
	})
	require.NoError(t, err)

	return m
}
