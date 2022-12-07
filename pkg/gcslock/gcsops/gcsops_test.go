// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package gcsops

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"storj.io/common/memory"
	"storj.io/common/testcontext"
	"storj.io/common/testrand"
)

func TestClient_BasicCycle(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	c, bucket := newClient(ctx, t), findBucket(ctx, t)

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

func newClient(ctx *testcontext.Context, t *testing.T) *Client {
	pathToJSONKey := os.Getenv("STORJ_TEST_GCSOPS_PATH_TO_JSON_KEY")

	if pathToJSONKey == "" {
		t.Skipf("Skipping %s without credentials provided", t.Name())
	}

	jsonKey, err := os.ReadFile(pathToJSONKey)
	require.NoError(t, err)

	c, err := NewClient(ctx, jsonKey)
	require.NoError(t, err)

	return c
}

func findBucket(ctx *testcontext.Context, t *testing.T) string {
	bucket := os.Getenv("STORJ_TEST_GCSOPS_BUCKET")

	if bucket == "" {
		t.Skipf("Skipping %s without bucket provided", t.Name())
	}

	return bucket
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
