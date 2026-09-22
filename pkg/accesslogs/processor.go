// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

// Package accesslogs can handle collection and upload of arbitrarily
// formatted server access logs in the fashion of S3's server access
// logging.
package accesslogs

import (
	"bytes"
	"context"
	"encoding/hex"
	"runtime/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/errs2"
	"storj.io/common/memory"
	"storj.io/common/sync2"
	"storj.io/common/uuid"
)

const (
	defaultEntryLimit         = 2 * memory.KiB
	defaultShipmentLimit      = 63 * memory.MiB
	defaultUploaderQueueLimit = 100
	defaultUploaderRetryLimit = 3

	lf     = '\n'
	lfSize = 1
)

var (
	// The scope keeps the name of the package's previous home in
	// storj.io/common, so dashboards and alerts on the existing metrics
	// don't go blank.
	mon              = monkit.ScopeNamed("storj.io/common/accesslogs")
	timedFlushLabels = pprof.Labels("accesslogs", "timedFlush")
)

// Key is a key that logs for the specified project ID and bucket can be
// queued.
//
// Logs are stored in the specified bucket under the specified prefix.
type Key struct {
	PublicProjectID uuid.UUID
	Bucket          string
	Prefix          string
}

// Entry represents a single log line of collected logs.
type Entry interface {
	Size() memory.Size
	String() string
}

// Processor is a log collection engine that works together with a
// concurrently running uploader tasked with uploading to the Storage
// implementation. Logs are collected, packaged and uploaded when a
// certain (configurable) size of the package is hit.
type Processor struct {
	log    *zap.Logger
	upload uploader

	timedFlushes  errs2.Group
	cancelFlushes sync2.Fence

	shutdownTimeout time.Duration

	defaultEntryLimit       memory.Size
	defaultShipmentLimit    memory.Size
	defaultShipmentInterval time.Duration

	globalLimit memory.Size

	// pendingWrites is used to prevent logical races between queuing
	// new entries and timed flushes. If we don't use it, we risk losing
	// entries because timed flush dereferences a parcel (to prevent
	// trash buildup), which could happen during queuing if we didn't
	// lock. RWMutex is used to deprioritize flushes from new writes.
	// This locking is global for all keys instead of being per-key like
	// the parcels map is, but it shouldn't be a big performance hit as
	// long as locking that happens during the timed flush is brief.
	pendingWrites sync.RWMutex
	parcels       sync.Map
	globalSize    atomic.Int64
}

// Options define how Processor should be configured when initialized.
type Options struct {
	DefaultEntryLimit       memory.Size   `user:"true" help:"log entry size limit" default:"2KiB"`
	DefaultShipmentLimit    memory.Size   `user:"true" help:"log file size limit" default:"63MiB"`
	DefaultShipmentInterval time.Duration `user:"true" help:"log file time limit regardless of size (0 means unlimited)" default:"1h"`
	UploadingOptions        struct {
		QueueLimit      int           `user:"true" help:"log file upload queue limit" default:"100"`
		RetryLimit      int           `user:"true" help:"maximum number of retries for log file uploads" default:"3"`
		ShutdownTimeout time.Duration `user:"true" help:"time limit waiting for queued logs to finish uploading when gateway is shutting down" default:"1m"`
	}
}

// NewProcessor returns initialized Processor.
func NewProcessor(log *zap.Logger, opts Options) *Processor {
	log = log.Named("access logs processor")

	if opts.DefaultEntryLimit <= 0 {
		opts.DefaultEntryLimit = defaultEntryLimit
	}
	if opts.DefaultShipmentLimit <= 0 {
		opts.DefaultShipmentLimit = defaultShipmentLimit
	}
	if opts.UploadingOptions.QueueLimit <= 0 {
		opts.UploadingOptions.QueueLimit = defaultUploaderQueueLimit
	}
	if opts.UploadingOptions.RetryLimit <= 0 {
		opts.UploadingOptions.RetryLimit = defaultUploaderRetryLimit
	}
	if opts.UploadingOptions.ShutdownTimeout <= 0 {
		opts.UploadingOptions.ShutdownTimeout = time.Minute
	}

	return &Processor{
		log: log,
		upload: newSequentialUploader(log, sequentialUploaderOptions{
			entryLimit:      opts.DefaultShipmentLimit,
			queueLimit:      opts.UploadingOptions.QueueLimit,
			retryLimit:      opts.UploadingOptions.RetryLimit,
			shutdownTimeout: opts.UploadingOptions.ShutdownTimeout,
		}),

		defaultEntryLimit:       opts.DefaultEntryLimit,
		defaultShipmentLimit:    opts.DefaultShipmentLimit,
		defaultShipmentInterval: opts.DefaultShipmentInterval,

		shutdownTimeout: opts.UploadingOptions.ShutdownTimeout,

		globalLimit: opts.DefaultShipmentLimit * 100,
	}
}

// QueueEntry saves another entry under key for packaging and upload.
// store is saved only for the first time the key is seen.
func (p *Processor) QueueEntry(store Storage, key Key, entry Entry) (err error) {
	defer mon.Task()(nil)(&err)

	entrySize := entry.Size().Int() + lfSize

	if g := p.globalSize.Load(); g+int64(entrySize) > p.globalLimit.Int64() {
		// NOTE(artur): this is a best-effort check; we could return an
		// error here, but we would have to flush immediately afterward.
		mon.Event("global_limit_exceeded")
		p.log.Warn("globalLimit exceeded", zap.Int64("limit", p.globalLimit.Int64()), zap.Int64("size", g))
	}

	p.pendingWrites.RLock()
	defer p.pendingWrites.RUnlock()

	actual, loaded := p.parcels.LoadOrStore(key, &parcel{
		// TODO(artur): make entryLimit & shipmentLimit configurable via
		// Entry.
		entryLimit:    p.defaultEntryLimit.Int(),
		shipmentLimit: p.defaultShipmentLimit.Int(),
		store:         store,
		bucket:        key.Bucket,
		prefix:        key.Prefix,
	})

	parcel := actual.(*parcel)

	if !loaded && p.defaultShipmentInterval > 0 {
		p.timedFlushes.Go(func() error {
			var flushErr error
			pprof.Do(context.Background(), timedFlushLabels, func(ctx context.Context) {
				// TODO(artur): make defaultShipmentInterval
				// configurable via Entry.
				flushErr = p.timedFlush(key, p.defaultShipmentInterval)
			})
			return flushErr
		})
	}

	if entrySize > parcel.entryLimit {
		return Error.Wrap(ErrTooLarge)
	}

	shipped, err := parcel.add(p.upload, entrySize, entry.String())
	if err != nil {
		return Error.Wrap(err)
	}

	mon.IntVal("globalLimit").Observe(p.globalSize.Add(int64(-shipped + entrySize)))

	return nil
}

func (p *Processor) timedFlush(key Key, interval time.Duration) error {
	t := time.NewTimer(interval)
	defer t.Stop()

	select {
	case <-p.cancelFlushes.Done():
		return nil
	case <-t.C:
		p.pendingWrites.Lock()
		actual, _ := p.parcels.LoadAndDelete(key)
		p.pendingWrites.Unlock()

		parcel := actual.(*parcel)

		shipped, err := parcel.flush(p.upload)

		mon.IntVal("globalLimit").Observe(p.globalSize.Add(int64(-shipped)))
		p.log.Debug("timed flush",
			zap.String("public_project_id", key.PublicProjectID.String()),
			zap.String("bucket", key.Bucket),
			zap.String("prefix", key.Prefix),
			zap.Int("size", shipped),
			zap.Error(err),
		)

		if err != nil {
			return errs.New("couldn't flush %s/%s/%s: %w", key.PublicProjectID, key.Bucket, key.Prefix, err)
		}
	}

	return nil
}

// Run starts Processor. It returns once Close has finished flushing, or once
// ctx is canceled.
//
// ctx is the parent context of every upload. Canceling it is a teardown of
// last resort: queued entries are dropped rather than flushed, so it must not
// be wired to a graceful shutdown signal. Close is the graceful path, and it
// may only be called once nothing can queue new entries anymore — while
// requests are still in flight, QueueEntry starts failing with ErrClosed.
func (p *Processor) Run(ctx context.Context) error {
	return Error.Wrap(p.upload.run(ctx))
}

// Close stops Processor. Upon call to Close, all buffers are flushed,
// and the call is blocked until all flushing and uploading is done.
//
// Close is like http.Server's Shutdown, which means it must be called
// while Processor is still Run-ning to gracefully shut it down. If it
// doesn't finish within the shutdown timeout, the remaining uploads are
// dropped and Close returns context.DeadlineExceeded.
//
// TODO(artur): rename to Shutdown?
// TODO(artur): make it take context.Context instead of exposing just the shutdown timer?
func (p *Processor) Close() (err error) {
	defer mon.Task()(nil)(&err)

	var g errs.Group

	// Flushing sends into the upload queue, which blocks while it's full and
	// run is stuck on a slow or wedged upload, before upload.close even arms
	// its own timeout. Aborting the uploader releases those sends, so Close as
	// a whole is bounded by the shutdown timeout.
	timeout := time.AfterFunc(p.shutdownTimeout, p.upload.abort)

	p.cancelFlushes.Release()
	g.Add(p.timedFlushes.Wait()...)

	p.parcels.Range(func(k, v any) bool {
		key, parcel := k.(Key), v.(*parcel)
		if err := parcel.close(p.upload); err != nil {
			p.log.Error("couldn't close",
				zap.String("public_project_id", key.PublicProjectID.String()),
				zap.String("bucket", key.Bucket),
				zap.String("prefix", key.Prefix),
				zap.Error(err),
			)
			g.Add(errs.New("couldn't close %s/%s/%s: %w", key.PublicProjectID, key.Bucket, key.Prefix, err))
		}
		return true
	})

	closeErr := p.upload.close()
	if !timeout.Stop() && closeErr == nil {
		closeErr = context.DeadlineExceeded
	}
	g.Add(closeErr)

	return Error.Wrap(g.Err())
}

type parcel struct {
	entryLimit    int
	shipmentLimit int

	store          Storage
	bucket, prefix string

	mu      sync.Mutex
	current bytes.Buffer
	closed  bool
}

func (p *parcel) add(upload uploader, size int, s string) (shipped int, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return 0, ErrClosed
	}

	currentSize := p.current.Len()
	// fast path
	if currentSize+size < p.shipmentLimit {
		p.current.WriteString(s)
		p.current.WriteByte(lf)
		return 0, nil
	}
	// slow…
	k, err := randomKey(p.prefix, time.Now())
	if err != nil {
		return 0, err
	}
	// we use cloneUnsafe here because we already have the lock.
	c, err := p.cloneUnsafe()
	if err != nil {
		return 0, err
	}
	if err = upload.queueUpload(p.store, p.bucket, k, c); err != nil {
		// FIXME(artur): rewind the buffer if we fail to upload.
		return 0, err
	}
	shipped = currentSize
	// add again
	p.current.WriteString(s)
	p.current.WriteByte(lf)
	return shipped, nil
}

// cloneUnsafe creates a thread-unsafe clone of the parcel.
func (p *parcel) cloneUnsafe() ([]byte, error) {
	c := bytes.NewBuffer(nil)
	if _, err := p.current.WriteTo(c); err != nil {
		return nil, err
	}
	return c.Bytes(), nil
}

// clone creates a thread-safe clone of the parcel.
func (p *parcel) clone() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.cloneUnsafe()
}

func (p *parcel) flush(upload uploader) (int, error) {
	// NOTE(artur): here we need to queue upload without limits because when we
	// flush before close, we really want to drain all parcels as we won't have
	// the chance to trigger shipment later on.
	k, err := randomKey(p.prefix, time.Now())
	if err != nil {
		return 0, err
	}
	c, err := p.clone()
	if err != nil {
		return 0, err
	}
	return len(c), upload.queueUploadWithoutQueueLimit(p.store, p.bucket, k, c)
}

func (p *parcel) close(upload uploader) error {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		p.mu.Unlock()
		_, err := p.flush(upload)
		return err
	}
	p.mu.Unlock()
	return nil
}

func randomKey(prefix string, t time.Time) (string, error) {
	// TODO(artur): let's return something like
	// [DestinationPrefix][YYYY]-[MM]-[DD]-[hh]-[mm]-[ss]-[UniqueString]
	// for now. We can make randomKey take a custom format later.
	key := new(strings.Builder)
	key.WriteString(prefix)
	key.WriteString(t.UTC().Format("2006-01-02-15-04-05-"))

	u, err := uniqueString()
	if err != nil {
		return "", err
	}
	key.WriteString(u)

	return key.String(), nil
}

func uniqueString() (string, error) {
	u, err := uuid.New()
	if err != nil {
		return "", err
	}
	var result [16]byte
	hex.Encode(result[0:16], u.Bytes()[0:8])
	return strings.ToUpper(string(result[:])), nil
}
