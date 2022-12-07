// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

// Package gcsops provides an API client implementing a fraction of Cloud
// Storage's API originally needed by gcslock and packages using it.
package gcsops

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Endpoint is the top-level part of request endpoints to access Cloud Storage.
const Endpoint = "https://storage.googleapis.com"

var (
	// Error is the error class for this package.
	Error = errs.Class("gcsops")

	// ErrNotFound is returned when the requested resource is not available.
	ErrNotFound = Error.New("not found")
	// ErrPreconditionFailed is returned when one or more conditions given in
	// the request header fields evaluated to false when tested on the server.
	ErrPreconditionFailed = Error.New("precondition failed")

	mon = monkit.Package()
)

// Client implements a fraction of Cloud Storage's API originally needed by
// gcslock and packages using it.
type Client struct {
	HTTPClient *http.Client
}

// NewClient properly initializes new Client. It awkwardly takes context.Context
// because it uses oauth2 that stores it.
func NewClient(ctx context.Context, jsonKey []byte) (_ *Client, err error) {
	defer mon.Task()(&ctx)(&err)

	c, err := google.CredentialsFromJSON(ctx, jsonKey, "https://www.googleapis.com/auth/devstorage.full_control")
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return &Client{HTTPClient: oauth2.NewClient(ctx, c.TokenSource)}, nil
}

// Delete deletes from the bucket. It uses XML API.
func (c *Client) Delete(ctx context.Context, headers http.Header, bucket, name string) (err error) {
	defer mon.Task()(&ctx)(&err)

	u := xmlAPIEndpoint(bucket, name)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return Error.Wrap(err)
	}
	req.Header = headers.Clone()

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return Error.Wrap(err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusPreconditionFailed:
		return ErrPreconditionFailed
	default:
		return Error.New("unexpected status: %s", resp.Status)
	}
}

// Download downloads from the bucket. It uses XML API.
func (c *Client) Download(ctx context.Context, bucket, name string) (_ io.ReadCloser, err error) {
	defer mon.Task()(&ctx)(&err)

	u := xmlAPIEndpoint(bucket, name)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	// The caller is responsible for closing the body.
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return resp.Body, nil
	case http.StatusNotFound:
		_ = resp.Body.Close()
		return nil, ErrNotFound
	default:
		_ = resp.Body.Close()
		return nil, Error.New("unexpected status: %s", resp.Status)
	}

}

// List lists the bucket. It uses JSON API.
func (c *Client) List(ctx context.Context, bucket, prefix string, recursive bool) (_ []string, err error) {
	defer mon.Task()(&ctx)(&err)

	var (
		list          []string
		nextPageToken string
	)
	for {
		q := make(url.Values)
		q.Set("fields", "nextPageToken,prefixes,items(name)")
		q.Set("prettyPrint", "false")
		q.Set("prefix", prefix)
		if !recursive {
			q.Set("delimiter", "/")
		}
		if len(nextPageToken) > 0 {
			q.Set("pageToken", nextPageToken)
		}

		u := fmt.Sprintf(Endpoint+"/storage/v1/b/%s/o", bucket) + "?" + q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, Error.Wrap(err)
		}

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			return nil, Error.Wrap(err)
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return nil, Error.Wrap(errs.New("unexpected status: %s", resp.Status))
		}

		var rawList listing
		if err = json.NewDecoder(resp.Body).Decode(&rawList); err != nil {
			_ = resp.Body.Close()
			return nil, Error.Wrap(err)
		}

		_ = resp.Body.Close()

		list = append(list, combineLists(rawList.Prefixes, rawList.Items)...)

		if len(rawList.NextPageToken) > 0 {
			nextPageToken = rawList.NextPageToken
		} else {
			break
		}
	}

	return list, nil
}

// Stat stats in the bucket. It uses XML API.
func (c *Client) Stat(ctx context.Context, bucket, name string) (_ http.Header, err error) {
	defer mon.Task()(&ctx)(&err)

	u := xmlAPIEndpoint(bucket, name)

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	defer func() { _ = resp.Body.Close() }()

	ret := resp.Header.Clone() // avoid resp lingering in memory

	switch resp.StatusCode {
	case http.StatusOK:
		return ret, nil
	case http.StatusNotFound:
		return nil, ErrNotFound
	default:
		return nil, Error.New("unexpected status: %s", resp.Status)
	}
}

// Upload uploads to the bucket. It uses XML API.
func (c *Client) Upload(ctx context.Context, headers http.Header, bucket, name string, body io.Reader) (err error) {
	defer mon.Task()(&ctx)(&err)

	u := xmlAPIEndpoint(bucket, name)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, body)
	if err != nil {
		return Error.Wrap(err)
	}
	req.Header = headers.Clone()

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return Error.Wrap(err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusPreconditionFailed:
		return ErrPreconditionFailed
	default:
		return Error.New("unexpected status: %s", resp.Status)
	}
}

func xmlAPIEndpoint(bucket, object string) string {
	return fmt.Sprintf(Endpoint+"/%s/%s", bucket, url.PathEscape(object))
}

type listing struct {
	NextPageToken string   `json:"nextPageToken"`
	Prefixes      []string `json:"prefixes"`
	Items         []item
}

type item struct {
	Name string `json:"name"`
}

// combineLists combines prefixes and items so that prefixes and items
// (flattened) are returned as one lexicographically-sorted list.
func combineLists(prefixes []string, items []item) []string {
	var (
		i, j   int
		result []string
	)

	for i < len(prefixes) && j < len(items) {
		if prefixes[i] < items[j].Name {
			result = append(result, prefixes[i])
			i++
		} else {
			result = append(result, items[j].Name)
			j++
		}
	}

	result = append(result, prefixes[i:]...)

	for _, v := range items[j:] {
		result = append(result, v.Name)
	}

	return result
}
