// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package gcsops

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeebo/errs"

	"storj.io/common/memory"
	"storj.io/common/testcontext"
	"storj.io/common/testrand"
	"storj.io/edge/pkg/internal/gcstest"
)

func TestClient_BasicCycle(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	jsonKey, bucket := fincCredentials(t)

	c := newClient(ctx, t, jsonKey)

	headers := make(http.Header)
	headers.Set("x-goog-if-generation-match", "0")
	headers.Set("Cache-Control", "no-store")
	headers.Set("x-goog-meta-test", "1")

	data := testrand.Bytes(memory.KiB)
	// 1st put should succeed
	require.NoError(t, c.Upload(ctx, headers, bucket, "o", bytes.NewReader(data)))
	// 2nd put should fail
	require.ErrorIs(t, c.Upload(ctx, headers, bucket, "o", bytes.NewReader(data)), ErrPreconditionFailed)

	actualHeaders, err := c.Stat(ctx, bucket, "o")
	require.NoError(t, err)
	assert.Equal(t, headers.Get("Cache-Control"), actualHeaders.Get("Cache-Control"))
	assert.Equal(t, headers.Get("x-goog-meta-test"), actualHeaders.Get("x-goog-meta-test"))

	require.ErrorIs(t, c.Delete(ctx, nil, bucket, "something else"), ErrNotFound)
	_, err = c.Download(ctx, bucket, "something else")
	require.ErrorIs(t, err, ErrNotFound)
	_, err = c.Stat(ctx, bucket, "something else")
	require.ErrorIs(t, err, ErrNotFound)

	rc, err := c.Download(ctx, bucket, "o")
	require.NoError(t, err)
	defer ctx.Check(rc.Close)
	actualData, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, data, actualData)

	// upload some objects to test listing
	for i := 1; i <= 3; i++ {
		require.NoError(t, c.Upload(ctx, nil, bucket, fmt.Sprintf("%d", i), nil))
		require.NoError(t, c.Upload(ctx, nil, bucket, fmt.Sprintf("%d/%d", i, i+1), nil))
		require.NoError(t, c.Upload(ctx, nil, bucket, fmt.Sprintf("%d/%d/%d", i, i+1, i+2), nil))
	}

	result, err := c.List(ctx, bucket, "", false)
	require.NoError(t, err)
	assert.Equal(t, []string{"1", "1/", "2", "2/", "3", "3/", "o"}, result)
	result, err = c.List(ctx, bucket, "1/", false)
	require.NoError(t, err)
	assert.Equal(t, []string{"1/2", "1/2/"}, result)
	result, err = c.List(ctx, bucket, "", true)
	require.NoError(t, err)
	assert.Equal(t, []string{"1", "1/2", "1/2/3", "2", "2/3", "2/3/4", "3", "3/4", "3/4/5", "o"}, result)
	result, err = c.List(ctx, bucket, "1/", true)
	require.NoError(t, err)
	assert.Equal(t, []string{"1/2", "1/2/3"}, result)

	headers = make(http.Header)
	headers.Set("x-goog-if-metageneration-match", "0")
	require.ErrorIs(t, c.Delete(ctx, headers, bucket, "o"), ErrPreconditionFailed)
	headers.Set("x-goog-if-metageneration-match", "1")
	require.NoError(t, c.Delete(ctx, headers, bucket, "o"))

	for i := 1; i <= 3; i++ {
		require.NoError(t, c.Delete(ctx, nil, bucket, fmt.Sprintf("%d", i)))
		require.NoError(t, c.Delete(ctx, nil, bucket, fmt.Sprintf("%d/%d", i, i+1)))
		require.NoError(t, c.Delete(ctx, nil, bucket, fmt.Sprintf("%d/%d/%d", i, i+1, i+2)))
	}

	result, err = c.List(ctx, bucket, "", true)
	require.NoError(t, err)
	assert.Empty(t, result)
}

func fincCredentials(t *testing.T) (jsonKey []byte, bucket string) {
	jsonKey, bucket, err := gcstest.FindCredentials()
	if errs.Is(err, gcstest.ErrCredentialsNotFound) {
		t.Skipf("Skipping %s without credentials/bucket provided", t.Name())
	}
	return jsonKey, bucket
}

func newClient(ctx *testcontext.Context, t *testing.T, jsonKey []byte) *Client {
	c, err := NewClient(ctx, jsonKey)
	require.NoError(t, err)
	return c
}

func TestCombineLists(t *testing.T) {
	for i, tt := range [...]struct {
		prefixes []string
		items    []item
		want     []string
	}{
		{
			prefixes: nil,
			items:    nil,
			want:     nil,
		},
		{
			prefixes: nil,
			items:    []item{{Name: "a"}, {Name: "b"}, {Name: "c"}},
			want:     []string{"a", "b", "c"},
		},
		{
			prefixes: []string{"d", "e", "f"},
			items:    nil,
			want:     []string{"d", "e", "f"},
		},
		{
			prefixes: []string{"b", "d", "f"},
			items:    []item{{Name: "a"}, {Name: "c"}, {Name: "g"}},
			want:     []string{"a", "b", "c", "d", "f", "g"},
		},

		{
			prefixes: []string{"b", "d", "f", "h"},
			items:    []item{{Name: "a"}, {Name: "g"}},
			want:     []string{"a", "b", "d", "f", "g", "h"},
		},
	} {
		assert.Equal(t, tt.want, combineLists(tt.prefixes, tt.items), i)
	}
}

func TestBadRequest(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	jsonKey, bucket := fincCredentials(t)

	c := newClient(ctx, t, jsonKey)

	invalidKey := string(testrand.RandAlphaNumeric(1025))

	require.ErrorIs(t, c.TestPermissions(ctx, invalidKey), APIError{
		Status:  "400 Bad Request",
		Message: "The specified bucket is not valid."})

	require.ErrorIs(t, c.Delete(ctx, http.Header{}, bucket, invalidKey), APIError{
		Status:  "400 Bad Request",
		Message: "The specified object name is not valid."})

	_, err := c.Download(ctx, bucket, invalidKey)
	require.ErrorIs(t, err, APIError{
		Status:  "400 Bad Request",
		Message: "The specified object name is not valid."})

	_, err = c.Stat(ctx, bucket, invalidKey)
	require.ErrorIs(t, err, APIError{Status: "400 Bad Request"})

	require.ErrorIs(t, c.Upload(ctx, http.Header{}, bucket, invalidKey, nil), APIError{
		Status:  "400 Bad Request",
		Message: "The specified object name is not valid."})
}

func TestResponseError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		body     string
		header   http.Header
		status   int
		expected error
	}{
		{
			name:     "GET missing body no content type",
			status:   http.StatusBadGateway,
			expected: APIError{Status: "502 Bad Gateway"},
		},
		{
			name: "JSON invalid response",
			body: "{asdasddf:235dfdf\\\\\\t\bnns\asdc/cv}",
			header: http.Header{
				"Content-Type": {"application/json; charset=UTF-8"},
			},
			status:   http.StatusBadGateway,
			expected: APIError{Status: "502 Bad Gateway"},
		},
		{
			name: "JSON missing fields",
			body: `{"error":{}}`,
			header: http.Header{
				"Content-Type": {"application/json; charset=UTF-8"},
			},
			status:   http.StatusBadGateway,
			expected: APIError{Status: "502 Bad Gateway"},
		},
		{
			name: "JSON missing body",
			header: http.Header{
				"Content-Type": {"application/json; charset=UTF-8"},
			},
			status:   http.StatusBadGateway,
			expected: APIError{Status: "502 Bad Gateway"},
		},
		{
			name: "JSON valid response",
			body: `{"error":{"message":"There was a problem"}}`,
			header: http.Header{
				"Content-Type": {"application/json; charset=UTF-8"},
			},
			status: http.StatusBadGateway,
			expected: APIError{
				Status:  "502 Bad Gateway",
				Message: "There was a problem",
			},
		},
		{
			name: "XML invalid response",
			body: `<?xml version="1.0" encoding="UTF-8"?>asdasddf:235dfdf\\\\\\t\bnns\asdc/cv`,
			header: http.Header{
				"Content-Type": {"application/xml; charset=UTF-8"},
			},
			status:   http.StatusBadGateway,
			expected: APIError{Status: "502 Bad Gateway"},
		},
		{
			name: "XML missing fields",
			body: `<?xml version="1.0" encoding="UTF-8"?><Error></Error>`,
			header: http.Header{
				"Content-Type": {"application/xml; charset=UTF-8"},
			},
			status:   http.StatusBadGateway,
			expected: APIError{Status: "502 Bad Gateway"},
		},
		{
			name: "XML missing body",
			header: http.Header{
				"Content-Type": {"application/xml; charset=UTF-8"},
			},
			status:   http.StatusBadGateway,
			expected: APIError{Status: "502 Bad Gateway"},
		},
		{
			name: "XML valid response",
			body: `<?xml version="1.0" encoding="UTF-8"?><Error><Message>There was a problem</Message></Error>`,
			header: http.Header{
				"Content-Type": {"application/xml; charset=UTF-8"},
			},
			status: http.StatusBadGateway,
			expected: APIError{
				Status:  "502 Bad Gateway",
				Message: "There was a problem",
			},
		},
		{
			name: "generic error unknown content type",
			body: `<?xml version="1.0" encoding="UTF-8"?><Error><Message>There was a problem</Message></Error>`,
			header: http.Header{
				"Content-Type": {"text/plain"},
			},
			status:   http.StatusBadGateway,
			expected: APIError{Status: "502 Bad Gateway"},
		},
		{
			name: "generic error 2xx status code",
			body: `<?xml version="1.0" encoding="UTF-8"?><Error><Message>There was a problem</Message></Error>`,
			header: http.Header{
				"Content-Type": {"application/xml; charset=UTF-8"},
			},
			status:   http.StatusOK,
			expected: APIError{Status: "200 OK"},
		},
		{
			name: "generic error 3xx status code",
			body: `<?xml version="1.0" encoding="UTF-8"?><Error><Message>There was a problem</Message></Error>`,
			header: http.Header{
				"Content-Type": {"application/xml; charset=UTF-8"},
			},
			status:   http.StatusSeeOther,
			expected: APIError{Status: "303 See Other"},
		},
		{
			name: "parsed error 4xx status code",
			body: `<?xml version="1.0" encoding="UTF-8"?><Error><Message>There was a problem</Message></Error>`,
			header: http.Header{
				"Content-Type": {"application/xml; charset=UTF-8"},
			},
			status: http.StatusBadRequest,
			expected: APIError{
				Status:  "400 Bad Request",
				Message: "There was a problem",
			},
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := testcontext.New(t)
			defer ctx.Cleanup()

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for k, v := range tc.header {
					w.Header().Set(k, strings.Join(v, ", "))
				}
				w.WriteHeader(tc.status)
				_, err := w.Write([]byte(tc.body))
				require.NoError(t, err)
			}))
			defer ts.Close()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL, nil)
			require.NoError(t, err)

			resp, err := http.DefaultClient.Do(req) //nolint:bodyclose
			require.NoError(t, err)
			defer ctx.Check(resp.Body.Close)

			require.ErrorIs(t, responseError(resp), tc.expected)
		})
	}
}
