// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package accesslogs

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/memory"
	"storj.io/common/sync2"
	"storj.io/uplink"
)

// Storage wraps the Put method that allows uploading to object storage.
type Storage interface {
	Put(ctx context.Context, bucket, key string, body []byte) error
}

var (
	_ Storage = (*noopStorage)(nil)
	_ Storage = (*inMemoryStorage)(nil)
	_ Storage = (*StorjStorage)(nil)
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

// StorjStorage is an implementation of Storage that allows uploading to
// Storj via libuplink.
type StorjStorage struct {
	access *uplink.Access
}

// NewStorjStorage creates a new instance of StorjStorage with the given access grant.
// It initializes and returns a pointer to the StorjStorage struct.
func NewStorjStorage(access *uplink.Access) *StorjStorage {
	return &StorjStorage{
		access: access,
	}
}

// SerializedAccessGrant returns a serialized form of the access grant used for this storage.
func (s StorjStorage) SerializedAccessGrant() (string, error) {
	return s.access.Serialize()
}

// Put saves body under bucket/key to Storj.
func (s StorjStorage) Put(ctx context.Context, bucket, key string, body []byte) (err error) {
	defer mon.Task()(&ctx)(&err)

	p, err := uplink.OpenProject(ctx, s.access)
	if err != nil {
		return err
	}
	defer func() { err = errs.Combine(err, p.Close()) }()
	u, err := p.UploadObject(ctx, bucket, key, nil)
	if err != nil {
		return err
	}
	if _, err = sync2.Copy(ctx, u, bytes.NewBuffer(body)); err != nil {
		return errs.Combine(err, u.Abort())
	}
	return u.Commit()
}

type uploader interface {
	queueUpload(store Storage, bucket, key string, body []byte) error
	queueUploadWithoutQueueLimit(store Storage, bucket, key string, body []byte) error
	run() error
	close() error
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

	closing      sync2.Event
	queueDrained sync2.Event
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

	u.queue <- upload{
		store:   store,
		bucket:  bucket,
		key:     key,
		body:    body,
		retries: 0,
	}

	return nil
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

	u.queue <- upload{
		store:   store,
		bucket:  bucket,
		key:     key,
		body:    body,
		retries: 0,
	}

	return nil
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
	} else {
		close(u.queue)
	}

	return nil
}

func (u *sequentialUploader) run() error {
	var closing bool
	for {
		select {
		case up := <-u.queue:
			// TODO(artur): we need to figure out what context we want
			// to pass here. WithTimeout(Background, …)?
			if err := up.store.Put(context.TODO(), up.bucket, up.key, up.body); err != nil {
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
				u.queue <- up // failure; don't decrement u.queueLen
				mon.Event("upload_failed")
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
