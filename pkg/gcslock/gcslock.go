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
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/sync/errgroup"

	"storj.io/common/sync2"
	"storj.io/gateway-mt/pkg/backoff"
)

const (
	expirationHeader = "x-goog-meta-expiration"
	gcsURL           = "https://storage.googleapis.com"
)

var (
	// Error is the error class for this package.
	Error errs.Class = "gcslock"
	mon              = monkit.Package()
)

// Mutex is a distributed lock implemented on top of Google Cloud Storage.
// NewMutex or NewDefaultMutex should always be used to construct a Mutex.
type Mutex struct {
	client *http.Client

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

	for {
		// Step 1: create the object at the given URL
		resp, err := m.put(ctx)
		if err != nil {
			return Error.Wrap(err)
		}
		_, err = sync2.Copy(ctx, io.Discard, resp.Body)
		if err = errs.Combine(err, resp.Body.Close()); err != nil {
			return Error.Wrap(err)
		}
		// Step 2: if creation is successful, then it means we've taken the lock
		if resp.StatusCode == http.StatusOK {
			// Step 2.1: start refreshing the lock in the background
			m.refreshCycle = sync2.NewCycle(m.refreshInterval)
			m.refreshCycle.SetDelayStart()
			m.refreshCycle.Start(ctx, m.refreshGroup, m.refresh)
			return nil
		}
		if resp.StatusCode != http.StatusPreconditionFailed {
			if err = m.backoff.Wait(ctx); err != nil {
				return Error.Wrap(err)
			}
			continue
		}
		// Step 3: if creation fails with a 412 Precondition Failed error
		// (meaning the object already exists), then...
		resp, err = m.head(ctx)
		if err != nil {
			return Error.Wrap(err)
		}
		_, err = sync2.Copy(ctx, io.Discard, resp.Body)
		if err = errs.Combine(err, resp.Body.Close()); err != nil {
			return Error.Wrap(err)
		}

		if m.shouldWait(ctx, resp.StatusCode, resp.Header) {
			if err = m.backoff.Wait(ctx); err != nil {
				return Error.Wrap(err)
			}
		}
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
	if err := m.refreshGroup.Wait(); err != nil {
		return Error.Wrap(err) // TODO(artur): ✓ just log it
	}
	// Step 2: delete the lock object at the given URL
	// Step 2.1: Use the x-goog-if-metageneration-match: [last known metageneration] header
	resp, err := m.delete(ctx, m.lastKnownMetageneration)
	if err != nil {
		return Error.Wrap(err)
	}
	_, err = sync2.Copy(ctx, io.Discard, resp.Body)
	if err = errs.Combine(err, resp.Body.Close()); err != nil {
		return Error.Wrap(err)
	}
	// Step 2.2: ignore the 412 Precondition Failed error, if any
	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusPreconditionFailed:
		return nil
	default:
		return Error.New("unexpected response status code: %d", resp.StatusCode)
	}
}

// NewMutex initializes new Mutex.
func NewMutex(
	ctx context.Context,
	jsonKey []byte,
	name, bucket string,
	ttl, refreshInterval time.Duration,
) (_ *Mutex, err error) {
	defer mon.Task()(&ctx)(&err)

	c, err := google.CredentialsFromJSON(ctx, jsonKey, "https://www.googleapis.com/auth/devstorage.full_control")
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return &Mutex{
		client:          oauth2.NewClient(ctx, c.TokenSource),
		name:            name,
		bucket:          bucket,
		ttl:             ttl,
		refreshInterval: refreshInterval,
		backoff: backoff.ExponentialBackoff{
			Max: 30 * time.Second,
			Min: time.Second,
		},
		refreshCycle:            new(sync2.Cycle), // will be recreated in Lock.
		refreshGroup:            new(errgroup.Group),
		lastKnownMetageneration: "1",
	}, nil
}

// NewDefaultMutex initializes new Mutex with recommended TTL and refresh
// interval.
func NewDefaultMutex(
	ctx context.Context,
	jsonKey []byte,
	name, bucket string,
) (_ *Mutex, err error) {
	defer mon.Task()(&ctx)(&err)

	return NewMutex(ctx, jsonKey, name, bucket, 5*time.Minute, 37*time.Second)
}

func (m *Mutex) put(ctx context.Context) (_ *http.Response, err error) {
	defer mon.Task()(&ctx)(&err)

	u := xmlAPIEndpoint(m.bucket, m.name)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("x-goog-if-generation-match", "0")
	req.Header.Add("Cache-Control", "no-store")
	req.Header.Add(expirationHeader, time.Now().Add(m.ttl).Format(time.RFC3339))

	return m.client.Do(req)
}

// refresh refreshes the lock's expiration.
//
// TODO(artur): refresh is currently not allowed to fail (it should be
// configurable, i.e., it should be allowed to fail, e.g., 3x at maximum).
//
// NOTE(artur): unfortunately, we have to use JSON API for this, not XML.
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
	u := jsonAPIEndpoint(m.bucket, m.name) + "?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, u, bytes.NewReader(b))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { err = errs.Combine(err, resp.Body.Close()) }()

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

func (m *Mutex) head(ctx context.Context) (_ *http.Response, err error) {
	defer mon.Task()(&ctx)(&err)

	u := xmlAPIEndpoint(m.bucket, m.name)

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
	if err != nil {
		return nil, err
	}

	return m.client.Do(req)
}

// shouldWait treats every error as transient.
func (m *Mutex) shouldWait(ctx context.Context, statusCode int, headers http.Header) bool {
	defer mon.Task()(&ctx)(nil)

	if statusCode != http.StatusOK {
		return statusCode != http.StatusNotFound
	}

	expiration, err := time.Parse(time.RFC3339, headers.Get(expirationHeader))
	if err != nil {
		return true
	}

	if time.Now().After(expiration) {
		resp, err := m.delete(ctx, headers.Get("x-goog-metageneration"))
		if err != nil {
			return true
		}
		_, err = sync2.Copy(ctx, io.Discard, resp.Body)
		if err = errs.Combine(err, resp.Body.Close()); err != nil {
			return true
		}
		return resp.StatusCode != http.StatusNoContent
	}

	return true
}

func (m *Mutex) delete(ctx context.Context, metageneration string) (_ *http.Response, err error) {
	defer mon.Task()(&ctx)(&err)

	u := xmlAPIEndpoint(m.bucket, m.name)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("x-goog-if-metageneration-match", metageneration)

	return m.client.Do(req)
}

func xmlAPIEndpoint(bucket, object string) string {
	return fmt.Sprintf(gcsURL+"/%s/%s", bucket, object)
}

func jsonAPIEndpoint(bucket, object string) string {
	return fmt.Sprintf(gcsURL+"/storage/v1/b/%s/o/%s", bucket, object)
}
