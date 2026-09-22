// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package accesslogs

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/zeebo/errs"
	"go.uber.org/zap/zaptest"

	"storj.io/common/memory"
	"storj.io/common/testcontext"
	"storj.io/common/testrand"
)

func TestLimits(t *testing.T) {
	t.Parallel()

	ctx := testcontext.New(t)

	log := zaptest.NewLogger(t)
	defer ctx.Check(log.Sync)

	s := noopStorage{}
	u := newSequentialUploader(log, sequentialUploaderOptions{
		entryLimit:      5 * memory.KiB,
		queueLimit:      2,
		retryLimit:      1,
		shutdownTimeout: time.Second,
	})

	for range 2 {
		require.NoError(t, u.queueUpload(s, "test", "test", testrand.Bytes(memory.KiB)))
	}
	require.ErrorIs(t, u.queueUpload(s, "test", "test", testrand.Bytes(memory.KiB)), ErrQueueLimit)
	require.ErrorIs(t, u.queueUpload(s, "test", "test", testrand.Bytes(6*memory.KiB)), ErrTooLarge)
	require.ErrorIs(t, u.queueUploadWithoutQueueLimit(s, "test", "test", testrand.Bytes(6*memory.KiB)), ErrTooLarge)
}

func TestQueueNoLimit(t *testing.T) {
	t.Parallel()

	ctx := testcontext.New(t)

	log := zaptest.NewLogger(t)
	defer ctx.Check(log.Sync)

	s := noopStorage{}
	u := newSequentialUploader(log, sequentialUploaderOptions{
		entryLimit:      5 * memory.KiB,
		queueLimit:      2,
		retryLimit:      1,
		shutdownTimeout: time.Second,
	})
	defer ctx.Check(u.close)
	ctx.Go(func() error { return u.run(ctx) })

	for range 10 {
		require.NoError(t, u.queueUploadWithoutQueueLimit(s, "test", "test", testrand.Bytes(memory.KiB)))
	}
}

type errorStorage struct {
}

func (s errorStorage) Put(ctx context.Context, bucket, key string, data []byte) error {
	return errs.New("retry error")
}

func TestQueueNoLimitErroringStorage(t *testing.T) {
	t.Parallel()

	ctx := testcontext.New(t)

	log := zaptest.NewLogger(t)
	defer ctx.Check(log.Sync)

	s := errorStorage{}
	u := newSequentialUploader(log, sequentialUploaderOptions{
		entryLimit:      5 * memory.KiB,
		queueLimit:      10,
		retryLimit:      1,
		shutdownTimeout: time.Second,
	})
	defer ctx.Check(u.close)
	ctx.Go(func() error { return u.run(ctx) })

	for range 10 {
		require.NoError(t, u.queueUploadWithoutQueueLimit(s, "test", "test", testrand.Bytes(memory.KiB)))
	}
}

// TestRunAbortsOnCanceledContext covers the teardown-of-last-resort path: run
// returns instead of waiting to be closed, stops accepting uploads, and lets a
// concurrent close return rather than blocking for the whole shutdownTimeout.
func TestRunAbortsOnCanceledContext(t *testing.T) {
	t.Parallel()

	ctx := testcontext.New(t)

	log := zaptest.NewLogger(t)
	defer ctx.Check(log.Sync)

	runCtx, cancel := context.WithCancel(ctx)

	s := noopStorage{}
	u := newSequentialUploader(log, sequentialUploaderOptions{
		entryLimit:      5 * memory.KiB,
		queueLimit:      10,
		retryLimit:      1,
		shutdownTimeout: time.Minute, // long enough that a blocked close would time the test out
	})

	done := make(chan error, 1)
	ctx.Go(func() error {
		done <- u.run(runCtx)
		return nil
	})

	require.NoError(t, u.queueUpload(s, "test", "test", testrand.Bytes(memory.KiB)))

	cancel()
	require.ErrorIs(t, <-done, context.Canceled)

	require.ErrorIs(t, u.queueUpload(s, "test", "test", testrand.Bytes(memory.KiB)), ErrClosed)
	require.ErrorIs(t, u.queueUploadWithoutQueueLimit(s, "test", "test", testrand.Bytes(memory.KiB)), ErrClosed)
	require.NoError(t, u.close())
}

// blockingStorage blocks in Put until ctx is canceled.
type blockingStorage struct {
	started chan struct{}
}

func (s blockingStorage) Put(ctx context.Context, bucket, key string, data []byte) error {
	s.started <- struct{}{}
	<-ctx.Done()
	return ctx.Err()
}

// TestAbortReleasesBlockedSend covers senders that are already blocked on a
// full queue when run aborts: nothing will ever dequeue again, so every send
// has to give up instead of blocking forever.
func TestAbortReleasesBlockedSend(t *testing.T) {
	t.Parallel()

	ctx := testcontext.New(t)

	log := zaptest.NewLogger(t)
	defer ctx.Check(log.Sync)

	runCtx, cancel := context.WithCancel(ctx)

	s := blockingStorage{started: make(chan struct{}, 1)}
	u := newSequentialUploader(log, sequentialUploaderOptions{
		entryLimit:      5 * memory.KiB,
		queueLimit:      1,
		retryLimit:      1,
		shutdownTimeout: time.Minute,
	})

	done := make(chan error, 1)
	ctx.Go(func() error {
		done <- u.run(runCtx)
		return nil
	})

	// the first upload wedges run in Put, the second one fills the queue.
	require.NoError(t, u.queueUploadWithoutQueueLimit(s, "test", "test", testrand.Bytes(memory.KiB)))
	<-s.started
	require.NoError(t, u.queueUploadWithoutQueueLimit(s, "test", "test", testrand.Bytes(memory.KiB)))

	// the rest are past the closed check, blocked on the full queue.
	const blocked = 2
	sent := make(chan error, blocked)
	for range blocked {
		ctx.Go(func() error {
			sent <- u.queueUploadWithoutQueueLimit(s, "test", "test", testrand.Bytes(memory.KiB))
			return nil
		})
	}
	require.Eventually(t, func() bool {
		u.mu.Lock()
		defer u.mu.Unlock()
		return u.queueLen == 2+blocked
	}, 10*time.Second, time.Millisecond)

	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
	for range blocked {
		require.ErrorIs(t, <-sent, ErrClosed)
	}
	// a send after the abort must not block either.
	require.ErrorIs(t, u.send(upload{store: s}), ErrClosed)
	require.NoError(t, u.close())
}

// failingStorage blocks in Put until release is closed, then fails.
type failingStorage struct {
	started chan struct{}
	release chan struct{}
}

func (s failingStorage) Put(ctx context.Context, bucket, key string, data []byte) error {
	s.started <- struct{}{}
	<-s.release
	return errs.New("failure")
}

// TestAbortReleasesBlockedRequeue covers run requeueing a failed upload while
// a blocked sender has taken the slot it freed: run is the only consumer, so
// the requeue must give up once the context is canceled.
func TestAbortReleasesBlockedRequeue(t *testing.T) {
	t.Parallel()

	ctx := testcontext.New(t)

	log := zaptest.NewLogger(t)
	defer ctx.Check(log.Sync)

	runCtx, cancel := context.WithCancel(ctx)

	s := failingStorage{started: make(chan struct{}, 1), release: make(chan struct{})}
	u := newSequentialUploader(log, sequentialUploaderOptions{
		entryLimit:      5 * memory.KiB,
		queueLimit:      1,
		retryLimit:      1,
		shutdownTimeout: time.Minute,
	})

	done := make(chan error, 1)
	ctx.Go(func() error {
		done <- u.run(runCtx)
		return nil
	})

	// the first upload is in Put, the second one fills the queue, the third
	// one is blocked on the full queue.
	require.NoError(t, u.queueUploadWithoutQueueLimit(s, "test", "test", testrand.Bytes(memory.KiB)))
	<-s.started
	require.NoError(t, u.queueUploadWithoutQueueLimit(s, "test", "test", testrand.Bytes(memory.KiB)))
	sent := make(chan error, 1)
	ctx.Go(func() error {
		sent <- u.queueUploadWithoutQueueLimit(s, "test", "test", testrand.Bytes(memory.KiB))
		return nil
	})
	require.Eventually(t, func() bool {
		u.mu.Lock()
		defer u.mu.Unlock()
		return u.queueLen == 3
	}, 10*time.Second, time.Millisecond)

	// fail the first upload, so run requeues it into the full queue.
	close(s.release)
	time.Sleep(50 * time.Millisecond)

	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
	require.ErrorIs(t, <-sent, ErrClosed)
}

func TestQueueErroringStorage(t *testing.T) {
	t.Parallel()

	ctx := testcontext.New(t)

	log := zaptest.NewLogger(t)
	defer ctx.Check(log.Sync)

	s := errorStorage{}
	u := newSequentialUploader(log, sequentialUploaderOptions{
		entryLimit:      5 * memory.KiB,
		queueLimit:      10,
		retryLimit:      1,
		shutdownTimeout: time.Second,
	})
	defer ctx.Check(u.close)
	ctx.Go(func() error { return u.run(ctx) })

	for range 10 {
		require.NoError(t, u.queueUpload(s, "test", "test", testrand.Bytes(memory.KiB)))
	}
}
