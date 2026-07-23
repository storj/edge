// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

// Package s3lock provides distributed locks to use with AWS S3. It is a port of
// storj.io/edge/pkg/gcslock to S3, using S3 conditional writes in place of GCS
// generation preconditions:
//
//   - acquire: PutObject with If-None-Match: * (atomic create)
//   - refresh: PutObject with If-Match: <etag> (extend the expiration)
//   - release: DeleteObject with If-Match: <etag>
//
// Like gcslock, it does not implement identities: ownership is tracked by the
// lock object's ETag, and `refresh` is not allowed to fail. Unlike gcslock,
// Unlock is idempotent: because S3 returns 412 Precondition Failed for a
// conditional delete of a missing object (rather than 404), a stale/missing
// lock and a lock that was taken over are indistinguishable, and both are
// treated as "already released". The If-Match ETag guarantees we never delete a
// lock we no longer own.
package s3lock

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"golang.org/x/sync/errgroup"

	"storj.io/common/sync2"
	"storj.io/edge/pkg/backoff"
)

// expirationKey is the object-metadata key holding the lock's expiration. The
// S3 SDK stores it as the x-amz-meta-expiration header and returns it lowercased.
const expirationKey = "expiration"

var (
	// Error is the error class for this package.
	Error errs.Class = "s3lock"

	// ErrPreconditionFailed is returned when a conditional request's
	// precondition (If-None-Match / If-Match) evaluated to false on the server.
	ErrPreconditionFailed = Error.New("precondition failed")
	// ErrNotFound is returned when the requested object does not exist.
	ErrNotFound = Error.New("not found")

	mon = monkit.Package()
)

// Mutex is a distributed lock implemented on top of AWS S3. NewMutex should
// always be used to construct a Mutex.
type Mutex struct {
	client *s3.Client
	logger Logger

	name string

	bucket               string
	ttl, refreshInterval time.Duration

	backoff       backoff.ExponentialBackoff
	refreshCycle  *sync2.Cycle
	refreshGroup  *errgroup.Group
	lastKnownETag string
}

// Options define how Mutex should be configured.
type Options struct {
	// Client is the S3 client to use. It must be set.
	Client *s3.Client
	// Name is the object key of the lock. It must be set.
	Name string
	// Bucket is the bucket the lock object lives in. It must be set.
	Bucket string
	// TTL's default is 5 minutes.
	TTL time.Duration
	// RefreshInterval's default is 37 seconds.
	RefreshInterval time.Duration
	// If Logger is not set, nothing will be logged.
	Logger Logger
}

// NewMutex initializes new Mutex. If TTL and RefreshInterval aren't set in opt,
// reasonable defaults are applied.
func NewMutex(ctx context.Context, opt Options) (_ *Mutex, err error) {
	defer mon.Task()(&ctx)(&err)

	if opt.Client == nil {
		return nil, Error.New("client must be set")
	}

	m := &Mutex{
		logger:          &wrappedLogger{logger: opt.Logger},
		client:          opt.Client,
		name:            opt.Name,
		bucket:          opt.Bucket,
		ttl:             opt.TTL,
		refreshInterval: opt.RefreshInterval,
		backoff: backoff.ExponentialBackoff{
			Max: 30 * time.Second,
			Min: time.Second,
		},
		refreshCycle: new(sync2.Cycle), // will be recreated in Lock.
		refreshGroup: new(errgroup.Group),
	}

	if m.ttl == 0 {
		m.ttl = 5 * time.Minute
	}
	if m.refreshInterval == 0 {
		m.refreshInterval = 37 * time.Second
	}

	return m, nil
}

// Lock locks m.
func (m *Mutex) Lock(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	// copy backoff so that we don't use the same one for every Lock.
	backoff := m.backoff

	for i := 1; ; i++ {
		// Step 1: create the lock object atomically (If-None-Match: *).
		if err = m.put(ctx); err != nil {
			if !errs.Is(err, ErrPreconditionFailed) {
				m.logger.Infof("waiting (attempt=%d,%s)", i, err)
				if err = backoff.Wait(ctx); err != nil {
					return Error.Wrap(err)
				}
				continue
			}
			// Creation failed because the object already exists.
			if m.shouldWait(ctx) {
				m.logger.Infof("waiting (attempt=%d,lock already exists)", i)
				if err = backoff.Wait(ctx); err != nil {
					return Error.Wrap(err)
				}
			}
			continue
		}
		// Step 2: creation succeeded, so we've taken the lock.
		// Step 2.1: start refreshing the lock in the background. put() has
		// already recorded the current ETag in m.lastKnownETag.
		m.refreshCycle = sync2.NewCycle(m.refreshInterval)
		m.refreshCycle.SetDelayStart()
		m.refreshCycle.Start(ctx, m.refreshGroup, m.refresh)
		m.logger.Infof("locked (attempt=%d)", i)
		return nil
	}
}

// Unlock unlocks m. It is idempotent: releasing a lock we no longer hold (taken
// over or already released) is not an error.
func (m *Mutex) Unlock(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	// Step 1: stop refreshing the lock in the background.
	if m.refreshCycle != nil {
		m.refreshCycle.Close()
		m.refreshCycle = nil
	}
	if err = m.refreshGroup.Wait(); err != nil {
		m.logger.Errorf("refresh cycle terminated with an error while locked: %s", err)
	}
	// Step 2: delete the lock object, but only if it still carries our ETag.
	err = m.delete(ctx, m.lastKnownETag)
	// Step 2.1: a missing object (S3 returns 412 for a conditional delete of a
	// missing object) or a lock taken over by someone else (also 412) both mean
	// "already released"; ignore them.
	if err != nil && !errs.Is(err, ErrPreconditionFailed) && !errs.Is(err, ErrNotFound) {
		return Error.New("unexpected response: %w", err)
	}
	m.logger.Infof("unlocked")
	return nil
}

func (m *Mutex) put(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	out, err := m.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:       aws.String(m.bucket),
		Key:          aws.String(m.name),
		IfNoneMatch:  aws.String("*"),
		CacheControl: aws.String("no-store"),
		Metadata:     map[string]string{expirationKey: time.Now().Add(m.ttl).Format(time.RFC3339)},
	})
	if err != nil {
		if isPreconditionFailed(err) {
			return ErrPreconditionFailed
		}
		return Error.Wrap(err)
	}
	m.lastKnownETag = aws.ToString(out.ETag)
	return nil
}

// refresh refreshes the lock's expiration by rewriting the object conditionally
// on our last known ETag.
//
// TODO: refresh is currently not allowed to fail (it should be configurable,
// i.e., it should be allowed to fail, e.g., 3x at maximum).
func (m *Mutex) refresh(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	out, err := m.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:       aws.String(m.bucket),
		Key:          aws.String(m.name),
		IfMatch:      aws.String(m.lastKnownETag),
		CacheControl: aws.String("no-store"),
		Metadata:     map[string]string{expirationKey: time.Now().Add(m.ttl).Format(time.RFC3339)},
	})
	if err != nil {
		return errs.New("unhealthy lock: %w", err)
	}
	m.lastKnownETag = aws.ToString(out.ETag)
	return nil
}

func (m *Mutex) shouldWait(ctx context.Context) bool {
	defer mon.Task()(&ctx)(nil)

	out, err := m.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(m.bucket),
		Key:    aws.String(m.name),
	})
	if err != nil {
		return !isNotFound(err)
	}

	expiration, err := time.Parse(time.RFC3339, out.Metadata[expirationKey])
	if err != nil {
		return true
	}

	if time.Now().After(expiration) {
		return m.delete(ctx, aws.ToString(out.ETag)) != nil
	}

	return true
}

func (m *Mutex) delete(ctx context.Context, etag string) (err error) {
	defer mon.Task()(&ctx)(&err)

	_, err = m.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket:  aws.String(m.bucket),
		Key:     aws.String(m.name),
		IfMatch: aws.String(etag),
	})
	if err != nil {
		if isPreconditionFailed(err) {
			return ErrPreconditionFailed
		}
		if isNotFound(err) {
			return ErrNotFound
		}
		return Error.Wrap(err)
	}
	return nil
}

// httpStatus extracts the HTTP status code from an AWS SDK response error, or 0.
func httpStatus(err error) int {
	var re interface{ HTTPStatusCode() int }
	if errors.As(err, &re) {
		return re.HTTPStatusCode()
	}
	return 0
}

// isPreconditionFailed reports whether err is a conditional-request failure. S3
// returns 412 Precondition Failed when a precondition is not met, and 409
// ConditionalRequestConflict when a concurrent write conflicts; both mean
// another actor won the race.
func isPreconditionFailed(err error) bool {
	switch httpStatus(err) {
	case 412, 409:
		return true
	default:
		return false
	}
}

func isNotFound(err error) bool {
	return httpStatus(err) == 404
}
