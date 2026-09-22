// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package accesslogs

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"storj.io/common/memory"
	"storj.io/common/sync2"
)

// Storage wraps the Put method that allows uploading to object storage.
type Storage interface {
	Put(ctx context.Context, bucket, key string, body []byte) error
}

var (
	_ Storage = (*noopStorage)(nil)
	_ Storage = (*inMemoryStorage)(nil)
)

type noopStorage struct{} // useful in tests

func (noopStorage) Put(context.Context, string, string, []byte) error {
	return nil
}

// inMemoryStorage is not thread-safe. Useful in tests.
type inMemoryStorage struct {
	buckets map[string]map[string][]byte
}

func newInMemoryStorage() *inMemoryStorage {
	return &inMemoryStorage{
		buckets: make(map[string]map[string][]byte),
	}
}

func (s *inMemoryStorage) getBucketContents(bucket string) map[string][]byte {
	return s.buckets[bucket]
}

func (s *inMemoryStorage) Put(_ context.Context, bucket, key string, body []byte) error {
	if _, ok := s.buckets[bucket]; !ok {
		s.buckets[bucket] = make(map[string][]byte)
	}

	s.buckets[bucket][key] = body

	return nil
}

type uploader interface {
	queueUpload(store Storage, bucket, key string, body []byte) error
	queueUploadWithoutQueueLimit(store Storage, bucket, key string, body []byte) error
	run(ctx context.Context) error
	close() error
	abort()
}

var _ uploader = (*sequentialUploader)(nil)

type upload struct {
	store   Storage
	bucket  string
	key     string
	body    []byte
	retries int
}

type sequentialUploader struct {
	log *zap.Logger

	entryLimit      memory.Size
	queueLimit      int
	retryLimit      int
	shutdownTimeout time.Duration

	mu          sync.Mutex
	queue       chan upload
	queueLen    int
	queueClosed bool
	aborted     bool

	closing      sync2.Event
	queueDrained sync2.Event
	// abortSignal is a Fence rather than an Event, because an abort has to
	// release every sender blocked in send, and any send that comes after it.
	abortSignal sync2.Fence
}

type sequentialUploaderOptions struct {
	entryLimit      memory.Size
	queueLimit      int
	retryLimit      int
	shutdownTimeout time.Duration
}

func newSequentialUploader(log *zap.Logger, opts sequentialUploaderOptions) *sequentialUploader {
	return &sequentialUploader{
		log:             log.Named("sequential uploader"),
		entryLimit:      opts.entryLimit,
		queueLimit:      opts.queueLimit,
		retryLimit:      opts.retryLimit,
		shutdownTimeout: opts.shutdownTimeout,
		queue:           make(chan upload, opts.queueLimit),
	}
}

var monQueueLength = mon.IntVal("queue_length")

func (u *sequentialUploader) queueUpload(store Storage, bucket, key string, body []byte) error {
	u.mu.Lock()
	if u.queueClosed {
		u.mu.Unlock()
		return ErrClosed
	}
	if len(body) > u.entryLimit.Int() {
		u.mu.Unlock()
		return ErrTooLarge
	} else if u.queueLen >= u.queueLimit {
		u.mu.Unlock()
		mon.Event("queue_limit_reached")
		u.log.Info("queue limit reached", zap.Int("limit", u.queueLimit))
		return ErrQueueLimit
	}
	u.queueLen++
	monQueueLength.Observe(int64(u.queueLen))
	u.mu.Unlock()

	return u.send(upload{
		store:   store,
		bucket:  bucket,
		key:     key,
		body:    body,
		retries: 0,
	})
}

func (u *sequentialUploader) queueUploadWithoutQueueLimit(store Storage, bucket, key string, body []byte) error {
	u.mu.Lock()
	if u.queueClosed {
		u.mu.Unlock()
		return ErrClosed
	}
	if len(body) > u.entryLimit.Int() {
		u.mu.Unlock()
		return ErrTooLarge
	}
	u.queueLen++
	monQueueLength.Observe(int64(u.queueLen))
	u.mu.Unlock()

	return u.send(upload{
		store:   store,
		bucket:  bucket,
		key:     key,
		body:    body,
		retries: 0,
	})
}

// send hands up to run. The queue can be full, since
// queueUploadWithoutQueueLimit bypasses the queue limit, so the send may block
// until run dequeues. If run aborts in the meantime, nothing will ever dequeue
// again, so the send gives up instead of blocking forever.
func (u *sequentialUploader) send(up upload) error {
	select {
	case u.queue <- up:
		return nil
	case <-u.abortSignal.Done():
		return ErrClosed
	}
}

// abort marks the queue closed without draining it. It's the teardown path:
// the context is gone, so there's nothing left to upload with. Queued uploads
// are dropped, and a close waiting for a drain that will never happen is
// released.
func (u *sequentialUploader) abort() {
	u.mu.Lock()
	u.queueClosed = true
	u.aborted = true
	u.mu.Unlock()

	u.abortSignal.Release()
	u.queueDrained.Signal()
}

func (u *sequentialUploader) close() error {
	u.mu.Lock()
	if u.queueClosed {
		u.mu.Unlock()
		return nil
	}
	u.queueClosed = true
	u.mu.Unlock()

	u.closing.Signal()

	ctx, cancel := context.WithTimeout(context.Background(), u.shutdownTimeout)
	defer cancel()

	if !u.queueDrained.Wait(ctx) {
		return ctx.Err()
	}

	u.mu.Lock()
	aborted := u.aborted
	u.mu.Unlock()

	// an aborted run may have released queueDrained while a queueUpload was
	// already past its closed check and about to send, so leave the channel
	// open for it. Nothing reads from it anymore either way.
	if !aborted {
		close(u.queue)
	}

	return nil
}

func (u *sequentialUploader) run(ctx context.Context) error {
	var closing bool
	for {
		select {
		case <-ctx.Done():
			u.abort()
			return ctx.Err()
		case <-u.abortSignal.Done():
			// Close gave up on its shutdown timeout; queued uploads are
			// dropped.
			return nil
		case up := <-u.queue:
			if err := up.store.Put(ctx, up.bucket, up.key, up.body); err != nil {
				if ctx.Err() != nil {
					// the upload failed because we're being torn down, not
					// because the store is unhealthy. Retrying is pointless.
					u.abort()
					return ctx.Err()
				}
				if up.retries == u.retryLimit {
					mon.Event("upload_dropped")
					u.log.Error("retry limit reached",
						zap.String("bucket", up.bucket),
						zap.String("prefix", up.key),
						zap.Error(err),
					)
					if done := u.decrementQueueLen(closing); done {
						return nil
					}
					continue // NOTE(artur): here we could spill to disk or something
				}
				up.retries++
				mon.Event("upload_failed")
				// the queue can be full with senders blocked behind it, and
				// run is the only consumer, so the requeue must not block
				// past a teardown.
				select {
				case u.queue <- up: // failure; don't decrement u.queueLen
				case <-u.abortSignal.Done():
					return nil
				case <-ctx.Done():
					u.abort()
					return ctx.Err()
				}
				continue
			}
			mon.Event("upload_successful")
			if done := u.decrementQueueLen(closing); done {
				return nil
			}
		case <-u.closing.Signaled():
			u.mu.Lock()
			if u.queueLen == 0 {
				u.mu.Unlock()
				u.queueDrained.Signal()
				return nil
			} else {
				u.mu.Unlock()
				closing = true
			}
		}
	}
}

func (u *sequentialUploader) decrementQueueLen(closing bool) bool {
	u.mu.Lock()
	u.queueLen--
	monQueueLength.Observe(int64(u.queueLen))
	if u.queueLen == 0 && closing {
		u.mu.Unlock()
		u.queueDrained.Signal()
		return true
	}
	u.mu.Unlock()
	return false
}
