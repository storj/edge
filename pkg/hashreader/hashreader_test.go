// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package hashreader_test

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"storj.io/common/testcontext"
	"storj.io/edge/pkg/hashreader"
)

func TestHashImplementations(t *testing.T) {
	sha256hr := hashreader.New(bytes.NewReader([]byte("test")), sha256.New())
	_, err := io.ReadAll(sha256hr)
	require.NoError(t, err)
	require.Equal(t, "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", fmt.Sprintf("%x", sha256hr.Sum()))

	md5hr := hashreader.New(bytes.NewReader([]byte("test")), md5.New())
	_, err = io.ReadAll(md5hr)
	require.NoError(t, err)
	require.Equal(t, "098f6bcd4621d373cade4e832627b4f6", fmt.Sprintf("%x", md5hr.Sum()))
}

func TestRead(t *testing.T) {
	hr := hashreader.New(bytes.NewBuffer([]byte{}), sha256.New())
	buf := make([]byte, 2)
	n, err := hr.Read(buf)
	require.ErrorIs(t, err, io.EOF)
	require.Zero(t, n)
	require.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", fmt.Sprintf("%x", hr.Sum()))

	hr = hashreader.New(bytes.NewBuffer([]byte("test")), sha256.New())
	buf = make([]byte, 2)
	n, err = hr.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "te", string(buf))
	require.Equal(t, n, 2)
	require.Equal(t, "2d6c9a90dd38f6852515274cde41a8cd8e7e1a7a053835334ec7e29f61b918dd", fmt.Sprintf("%x", hr.Sum()))
}

func TestReaderFile(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	path := ctx.File("hashreader")
	require.NoError(t, os.WriteFile(path, []byte("test"), 0600))

	f, err := os.Open(path)
	require.NoError(t, err)
	defer ctx.Check(f.Close)

	hr := hashreader.New(f, sha256.New())
	_, err = io.ReadAll(hr)
	require.NoError(t, err)
	require.Equal(t, "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", fmt.Sprintf("%x", hr.Sum()))
}

func TestReaderDownload(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("test"))
		require.NoError(t, err)
	}))
	defer srv.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req) //nolint:bodyclose
	require.NoError(t, err)
	defer ctx.Check(resp.Body.Close)

	hr := hashreader.New(resp.Body, sha256.New())
	_, err = io.ReadAll(hr)
	require.NoError(t, err)
	require.Equal(t, "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", fmt.Sprintf("%x", hr.Sum()))
}
