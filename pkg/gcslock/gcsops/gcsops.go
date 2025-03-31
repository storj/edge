// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

// Package gcsops provides an API client implementing a fraction of Cloud
// Storage's API originally needed by gcslock and packages using it.
package gcsops

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"

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

// TestPermissions does a self-check of the current user's permissions in GCS.
// It returns nil if all permissions are correct, otherwise an error about
// the missing permission or error contacting the API.
func (c *Client) TestPermissions(ctx context.Context, bucket string) (err error) {
	defer mon.Task()(&ctx)(&err)

	q := make(url.Values)
	q.Add("permissions", "storage.objects.delete")
	q.Add("permissions", "storage.objects.get")
	q.Add("permissions", "storage.objects.list")
	q.Add("permissions", "storage.objects.create")

	// Remove any prefix from bucket
	b, _, _ := strings.Cut(bucket, "/")

	u := fmt.Sprintf(Endpoint+"/storage/v1/b/%s/iam/testPermissions", b) + "?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return Error.Wrap(err)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return Error.Wrap(err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return Error.Wrap(responseError(resp))
	}

	return nil
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
		return Error.Wrap(responseError(resp))
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
		err = responseError(resp)
		_ = resp.Body.Close()
		return nil, Error.Wrap(err)
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
			err = responseError(resp)
			_ = resp.Body.Close()
			return nil, Error.Wrap(err)
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
		return nil, Error.Wrap(responseError(resp))
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
		return Error.Wrap(responseError(resp))
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

// APIError is an API response error from Google Cloud Storage.
//
// See the following docs for more details:
//   - https://cloud.google.com/storage/docs/json_api/v1/status-codes
//   - https://cloud.google.com/storage/docs/xml-api/reference-status
type APIError struct {
	// Status is the HTTP status (e.g. 502 Gateway Timeout) from the response.
	Status string

	// Message contains details of the error.
	Message string `json:"message" xml:"Message"`
}

// Error implements the error interface.
func (e APIError) Error() string {
	msg := "unexpected status: " + e.Status
	if e.Message != "" {
		msg += fmt.Sprintf(": %q", e.Message)
	}
	return msg
}

// responseError parses the error document body and returns an error.
// For a list of the responses, see the following docs:
//   - https://cloud.google.com/storage/docs/json_api/v1/status-codes
//   - https://cloud.google.com/storage/docs/xml-api/reference-status
//
// If we encounter an unknown status code or Content-Type header value
// then an error with just the status is returned.
//
// Some responses don't have a body, even if they respond with a content
// type header like "application/xml". This speculatively parses and ignores
// any errors. If parsing errors were encountered then an error with just the
// status is returned.
func responseError(resp *http.Response) error {
	apiErr := APIError{
		Status: resp.Status,
	}

	contentType := func(value string) bool {
		for _, v := range resp.Header.Values("Content-Type") {
			mediatype, _, _ := mime.ParseMediaType(v)
			if strings.EqualFold(mediatype, value) {
				return true
			}
		}
		return false
	}

	switch {
	case resp.StatusCode >= 400 && contentType("application/json"):
		apiResp := struct {
			Error *APIError `json:"error"`
		}{
			Error: &apiErr,
		}
		_ = json.NewDecoder(resp.Body).Decode(&apiResp)
	case resp.StatusCode >= 400 && contentType("application/xml"):
		_ = xml.NewDecoder(resp.Body).Decode(&apiErr)
	}

	return apiErr
}
