// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

// Package gcslock provides distributed locks to use with Google Cloud Storage.
// The distributed locking algorithm is based on the algorithm from
// https://www.joyfulbikeshedding.com/blog/2021-05-19-robust-distributed-locking-algorithm-based-on-google-cloud-storage.html.
//
// It does not implement identities, and `refresh` is not allowed to fail.
package gcslock

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"golang.org/x/sync/errgroup"

	"storj.io/common/sync2"
	"storj.io/gateway-mt/pkg/backoff"
	"storj.io/gateway-mt/pkg/gcslock/gcsops"
)

const expirationHeader = "x-goog-meta-expiration"

var (
	// Error is the error class for this package.
	Error errs.Class = "gcslock"
	mon              = monkit.Package()
)

// Mutex is a distributed lock implemented on top of Google Cloud Storage.
// NewMutex should always be used to construct a Mutex.
type Mutex struct {
	client *gcsops.Client
	logger Logger

	name string

	bucket               string
	ttl, refreshInterval time.Duration

	backoff                 backoff.ExponentialBackoff
	refreshCycle            *sync2.Cycle
	refreshGroup            *errgroup.Group
	lastKnownMetageneration string
}

// Lock locks m.
func (m *Mutex) Lock(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	for i := 1; ; i++ {
		// Step 1: create the object at the given URL
		if err = m.put(ctx); err != nil {
			if !errs.Is(err, gcsops.ErrPreconditionFailed) {
				m.logger.Infof("waiting (attempt=%d,%s)", i, err)
				if err = m.backoff.Wait(ctx); err != nil {
					return Error.Wrap(err)
				}
				continue
			}
			// If creation fails with a 412 Precondition Failed error (meaning
			// the object already exists), then...
			if m.shouldWait(ctx) {
				m.logger.Infof("waiting (attempt=%d,lock already exists)", i)
				if err = m.backoff.Wait(ctx); err != nil {
					return Error.Wrap(err)
				}
			}
			continue
		}
		// Step 2: if creation is successful, then it means we've taken the lock
		// Step 2.1: start refreshing the lock in the background
		m.refreshCycle = sync2.NewCycle(m.refreshInterval)
		m.refreshCycle.SetDelayStart()
		m.refreshCycle.Start(ctx, m.refreshGroup, m.refresh)
		m.logger.Infof("locked (attempt=%d)", i)
		return nil
	}
}

// Unlock unlocks m.
func (m *Mutex) Unlock(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	// Step 1: stop refreshing the lock in the background
	if m.refreshCycle != nil {
		m.refreshCycle.Close()
		m.refreshCycle = nil
	}
	if err = m.refreshGroup.Wait(); err != nil {
		m.logger.Errorf("refresh cycle terminated with an error while locked: %s", err)
	}
	// Step 2: delete the lock object at the given URL
	// Step 2.1: Use the x-goog-if-metageneration-match: [last known metageneration] header
	err = m.delete(ctx, m.lastKnownMetageneration)
	// Step 2.2: ignore the 412 Precondition Failed error, if any
	if err != nil && !errs.Is(err, gcsops.ErrPreconditionFailed) {
		return Error.New("unexpected response: %w", err)
	}
	m.logger.Infof("unlocked")
	return nil
}

// Options define how Mutex should be configured.
type Options struct {
	// JSONKey must be set except when Client is set.
	JSONKey []byte
	Name    string
	Bucket  string
	// TTL's default is 5 minutes.
	TTL time.Duration
	// RefreshInterval's default is 37 seconds.
	RefreshInterval time.Duration
	// If Logger is not set, nothing will be logged.
	Logger Logger
	// If Client is not set, a new one will be created.
	Client *gcsops.Client
}

// NewMutex initializes new Mutex. If TTL and RefreshInterval aren't set in opt,
// reasonable defaults are applied.
func NewMutex(ctx context.Context, opt Options) (_ *Mutex, err error) {
	defer mon.Task()(&ctx)(&err)

	if opt.Client == nil {
		opt.Client, err = gcsops.NewClient(ctx, opt.JSONKey)
		if err != nil {
			return nil, Error.Wrap(err)
		}
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
		refreshCycle:            new(sync2.Cycle), // will be recreated in Lock.
		refreshGroup:            new(errgroup.Group),
		lastKnownMetageneration: "1",
	}

	if m.ttl == 0 {
		m.ttl = 5 * time.Minute
	}
	if m.refreshInterval == 0 {
		m.refreshInterval = 37 * time.Second
	}

	return m, nil
}

func (m *Mutex) put(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	headers := make(http.Header)
	headers.Add("x-goog-if-generation-match", "0")
	headers.Add("Cache-Control", "no-store")
	headers.Add(expirationHeader, time.Now().Add(m.ttl).Format(time.RFC3339))

	return m.client.Upload(ctx, headers, m.bucket, m.name, nil)
}

// refresh refreshes the lock's expiration.
//
// TODO(artur): refresh is currently not allowed to fail (it should be
// configurable, i.e., it should be allowed to fail, e.g., 3x at maximum).
//
// NOTE(artur): refresh uses custom code to call GCS because gcsops does not
// export updating metadata. We might backport this code to gcsops, but it's
// very specific to this package.
func (m *Mutex) refresh(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	reqData := struct {
		Metadata map[string]string `json:"metadata"`
	}{
		Metadata: map[string]string{
			"expiration": time.Now().Add(m.ttl).Format(time.RFC3339),
		},
	}

	b, err := json.Marshal(reqData)
	if err != nil {
		return err
	}

	q := url.Values{
		"fields":                {"metageneration"},
		"ifMetagenerationMatch": {m.lastKnownMetageneration},
		"prettyPrint":           {"false"},
	}
	u := fmt.Sprintf(gcsops.Endpoint+"/storage/v1/b/%s/o/%s", m.bucket, url.PathEscape(m.name)) + "?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, u, bytes.NewReader(b))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return errs.New("unhealthy lock: ret. status code: %d", resp.StatusCode)
	}

	var respData struct {
		Metageneration string `json:"metageneration"`
	}

	if err = json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return err
	}

	m.lastKnownMetageneration = respData.Metageneration

	return nil
}

// shouldWait treats every error as transient.
func (m *Mutex) shouldWait(ctx context.Context) bool {
	defer mon.Task()(&ctx)(nil)

	headers, err := m.client.Stat(ctx, m.bucket, m.name)
	if err != nil {
		return !errs.Is(err, gcsops.ErrNotFound)
	}

	expiration, err := time.Parse(time.RFC3339, headers.Get(expirationHeader))
	if err != nil {
		return true
	}

	if time.Now().After(expiration) {
		return m.delete(ctx, headers.Get("x-goog-metageneration")) != nil
	}

	return true
}

func (m *Mutex) delete(ctx context.Context, metageneration string) (err error) {
	defer mon.Task()(&ctx)(&err)

	headers := make(http.Header)
	headers.Add("x-goog-if-metageneration-match", metageneration)

	return m.client.Delete(ctx, headers, m.bucket, m.name)
}
