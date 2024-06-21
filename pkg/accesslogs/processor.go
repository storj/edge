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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spacemonkeygo/monkit/v3"
	"go.uber.org/zap"

	"storj.io/common/memory"
	"storj.io/common/uuid"
	"storj.io/uplink"
)

const (
	defaultEntryLimit    = 2 * memory.KiB
	defaultShipmentLimit = 63 * memory.MiB
)

var mon = monkit.Package()

// Key is a key that logs for the specified project ID and bucket can be
// queued. It's not a key under which packed logs are saved.
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

	defaultEntryLimit    memory.Size
	defaultShipmentLimit memory.Size

	globalLimit memory.Size

	parcels    sync.Map
	globalSize uint64
}

// Options define how Processor should be configured when initialized.
type Options struct {
	DefaultEntryLimit    memory.Size
	DefaultShipmentLimit memory.Size
	UploadingOptions     struct {
		QueueLimit      int
		RetryLimit      int
		ShutdownTimeout time.Duration
	}
}

// NewProcessor returns initialized Processor.
func NewProcessor(log *zap.Logger, store Storage, opts Options) *Processor {
	log = log.Named("access logs processor")

	if opts.DefaultEntryLimit == 0 {
		opts.DefaultEntryLimit = defaultEntryLimit
	}
	if opts.DefaultShipmentLimit == 0 {
		opts.DefaultShipmentLimit = defaultShipmentLimit
	}
	if opts.UploadingOptions.QueueLimit == 0 {
		opts.UploadingOptions.QueueLimit = 100
	}
	if opts.UploadingOptions.RetryLimit == 0 {
		opts.UploadingOptions.RetryLimit = 3
	}
	if opts.UploadingOptions.ShutdownTimeout == 0 {
		opts.UploadingOptions.ShutdownTimeout = time.Minute
	}

	return &Processor{
		log: log,
		upload: newSequentialUploader(log, store, sequentialUploaderOptions{
			entryLimit:      opts.DefaultShipmentLimit,
			queueLimit:      opts.UploadingOptions.QueueLimit,
			retryLimit:      opts.UploadingOptions.RetryLimit,
			shutdownTimeout: opts.UploadingOptions.ShutdownTimeout,
		}),
		defaultEntryLimit:    opts.DefaultEntryLimit,
		defaultShipmentLimit: opts.DefaultShipmentLimit,
	}
}

// QueueEntry saves another entry under key for packaging and upload.
// Provided access will be used for upload.
//
// TODO(artur): I think we should pass Storage here instead of
// uplink.Access. Then Processor and uploader doesn't have to be
// configured with Storage and the destination store can be specified
// per parcel.
func (p *Processor) QueueEntry(access *uplink.Access, key Key, entry Entry) (err error) {
	entrySize := entry.Size().Int()

	if g := atomic.LoadUint64(&p.globalSize); g+uint64(entrySize) > uint64(p.globalLimit.Int()) {
		// NOTE(artur): we could return an error here, but we would have
		// to flush immediately afterward.
		mon.Event("global_size_exceeded")
	}

	loaded, _ := p.parcels.LoadOrStore(key, &parcel{
		// TODO(artur): make entryLimit & shipmentLimit configurable via
		// Entry.
		entryLimit:    p.defaultEntryLimit.Int(),
		shipmentLimit: p.defaultShipmentLimit.Int(),
		access:        access,
		bucket:        key.Bucket,
		prefix:        key.Prefix,
	})

	parcel := loaded.(*parcel)

	if entrySize > parcel.entryLimit {
		return Error.Wrap(ErrTooLarge)
	}

	shipped, err := parcel.add(p.upload, entrySize, entry.String())
	if err != nil {
		return Error.Wrap(err)
	}

	if shipped > 0 {
		atomic.StoreUint64(&p.globalSize, -uint64(shipped-entrySize))
	} else {
		atomic.StoreUint64(&p.globalSize, uint64(entrySize))
	}

	return nil
}

// Run starts Processor.
func (p *Processor) Run(ctx context.Context) error {
	return Error.Wrap(p.upload.run(ctx))
}

// Close stops Processor. Upon call to Close, all buffers are flushed,
// and the call is blocked until all flushing and uploading is done.
func (p *Processor) Close() error {
	p.parcels.Range(func(k, v any) bool {
		key, parcel := k.(Key), v.(*parcel)
		if err := parcel.close(p.upload); err != nil {
			p.log.Error("couldn't close",
				zap.String("PublicProjectID", key.PublicProjectID.String()),
				zap.String("Bucket", key.Bucket),
				zap.String("Prefix", key.Prefix),
				zap.Error(err),
			)
		}
		return true
	})
	return Error.Wrap(p.upload.close())
}

type parcel struct {
	entryLimit, shipmentLimit int

	access         *uplink.Access
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
	if currentSize+size+1 < p.shipmentLimit {
		p.current.WriteString(s)
		p.current.WriteRune('\n')
		return 0, nil
	}
	// slow…
	k, err := randomKey(p.prefix, time.Now())
	if err != nil {
		return 0, err
	}
	c := bytes.NewBuffer(nil)
	if _, err = p.current.WriteTo(c); err != nil {
		return 0, err
	}
	if err = upload.queueUpload(p.access, p.bucket, k, c.Bytes()); err != nil {
		return 0, err
	}
	shipped = currentSize
	// add again
	p.current.WriteString(s)
	p.current.WriteRune('\n')
	return shipped, nil
}

func (p *parcel) flush(upload uploader) error {
	// NOTE(artur): here we need to queue upload without limits because when we
	// flush before close, we really want to drain all parcels as we won't have
	// the chance to trigger shipment later on.
	k, err := randomKey(p.prefix, time.Now())
	if err != nil {
		return err
	}
	c := bytes.NewBuffer(nil)
	if _, err = p.current.WriteTo(c); err != nil {
		return err
	}
	return upload.queueUploadWithoutQueueLimit(p.access, p.bucket, k, c.Bytes())
}

func (p *parcel) close(upload uploader) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.closed {
		p.closed = true
		return p.flush(upload)
	}
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
