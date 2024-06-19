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
//
// Storage is quite specific to libuplink at the moment. It could be
// made generic if there's enough reason to make it so.
type Storage interface {
	Put(ctx context.Context, access *uplink.Access, bucket, key string, body []byte) error
}

var (
	_ Storage = (*noopStorage)(nil)
	_ Storage = (*inMemoryStorage)(nil)
	_ Storage = (*StorjStorage)(nil)
)

type noopStorage struct{} // useful in tests

func (noopStorage) Put(context.Context, *uplink.Access, string, string, []byte) error {
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

func (s *inMemoryStorage) Put(_ context.Context, _ *uplink.Access, bucket, key string, body []byte) error {
	if _, ok := s.buckets[bucket]; !ok {
		s.buckets[bucket] = make(map[string][]byte)
	}

	s.buckets[bucket][key] = body

	return nil
}

// StorjStorage is an implementation of Storage that allows uploading to
// Storj via libuplink.
type StorjStorage struct{}

// Put saves body under bucket/key to Storj.
func (s StorjStorage) Put(ctx context.Context, access *uplink.Access, bucket, key string, body []byte) (err error) {
	p, err := uplink.OpenProject(ctx, access)
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
	queueUpload(access *uplink.Access, bucket, key string, body []byte) error
	queueUploadWithoutQueueLimit(access *uplink.Access, bucket, key string, body []byte) error
	run(ctx context.Context) error
	close() error
}

var _ uploader = (*sequentialUploader)(nil)

type upload struct {
	access  *uplink.Access
	bucket  string
	key     string
	body    []byte
	retries int
}

type sequentialUploader struct {
	log   *zap.Logger
	store Storage

	entryLimit      memory.Size
	queueLimit      int
	retryLimit      int
	shutdownTimeout time.Duration

	mu           sync.Mutex
	queue        chan upload
	queueLen     int
	queueDrained sync2.Event
	closed       bool
}

type sequentialUploaderOptions struct {
	entryLimit      memory.Size
	queueLimit      int
	retryLimit      int
	shutdownTimeout time.Duration
}

func newSequentialUploader(log *zap.Logger, store Storage, opts sequentialUploaderOptions) *sequentialUploader {
	return &sequentialUploader{
		log:             log.Named("sequential uploader"),
		store:           store,
		entryLimit:      opts.entryLimit,
		queueLimit:      opts.queueLimit,
		retryLimit:      opts.retryLimit,
		shutdownTimeout: opts.shutdownTimeout,
		queue:           make(chan upload, opts.queueLimit),
	}
}

func (u *sequentialUploader) queueUpload(access *uplink.Access, bucket, key string, body []byte) error {
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return ErrClosed
	}
	if len(body) > u.entryLimit.Int() {
		u.mu.Unlock()
		return ErrTooLarge
	} else if u.queueLen >= u.queueLimit {
		u.mu.Unlock()
		return ErrQueueLimit
	}
	u.queueLen++
	u.mu.Unlock()

	u.queue <- upload{
		access:  access,
		bucket:  bucket,
		key:     key,
		body:    body,
		retries: 0,
	}

	return nil
}

func (u *sequentialUploader) queueUploadWithoutQueueLimit(access *uplink.Access, bucket, key string, body []byte) error {
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return ErrClosed
	}
	if len(body) > u.entryLimit.Int() {
		u.mu.Unlock()
		return ErrTooLarge
	}
	u.queueLen++
	u.mu.Unlock()

	u.queue <- upload{
		access:  access,
		bucket:  bucket,
		key:     key,
		body:    body,
		retries: 0,
	}

	return nil
}

func (u *sequentialUploader) close() error {
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return nil
	}
	u.closed = true
	u.mu.Unlock()

	close(u.queue)

	ctx, cancel := context.WithTimeout(context.Background(), u.shutdownTimeout)
	defer cancel()

	if !u.queueDrained.Wait(ctx) {
		return ctx.Err()
	}

	return nil
}

func (u *sequentialUploader) run(ctx context.Context) error {
	for up := range u.queue {
		if err := u.store.Put(ctx, up.access, up.bucket, up.key, up.body); err != nil {
			if up.retries == u.retryLimit {
				u.log.Error("retry limit reached",
					zap.String("bucket", up.bucket),
					zap.String("prefix", up.key),
					zap.Error(err),
				)
				u.mu.Lock()
				u.queueLen--
				u.mu.Unlock()
				continue // NOTE(artur): here we could spill to disk or something
			}
			up.retries++
			u.queue <- up // failure; don't decrement u.queueLen
		}
		u.mu.Lock()
		u.queueLen--
		u.mu.Unlock()
	}
	u.queueDrained.Signal()
	return nil
}
