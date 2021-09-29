// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"storj.io/common/testcontext"
)

func TestV4MultipartCredentials(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	body := `-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="X-Amz-Signature"

X-Amz-Signature
-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="X-Amz-Date"

20060102T150405Z
-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="X-Amz-Credential"

AccessKey/20000101/region/s3/aws4_request
-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="file1"; filename="plain.txt"
Content-Type: text/plain

This is some plain text.

-----------------------------9051914041544843365972754266--`
	req, err := http.NewRequestWithContext(ctx, "POST", "", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=---------------------------9051914041544843365972754266")

	verify := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, ok := GetAccessKey(r.Context())
		require.True(t, ok)
		require.Equal(t, "AccessKey", key)
		require.Nil(t, r.MultipartForm)
		err = r.ParseMultipartForm(4096)
		require.NoError(t, err)
		require.Equal(t, "20060102T150405Z", r.MultipartForm.Value["X-Amz-Date"][0])
		require.Equal(t, "AccessKey/20000101/region/s3/aws4_request", r.MultipartForm.Value["X-Amz-Credential"][0])
		require.Equal(t, "X-Amz-Signature", r.MultipartForm.Value["X-Amz-Signature"][0])
	})

	AccessKey(verify).ServeHTTP(nil, req)
}

func TestV2MultipartCredentials(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	body := `-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="Signature"

Signature
-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="AWSAccessKeyId"

AccessKey
-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="file1"; filename="plain.txt"
Content-Type: text/plain

This is some plain text.

-----------------------------9051914041544843365972754266--`
	req, err := http.NewRequestWithContext(ctx, "POST", "", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=---------------------------9051914041544843365972754266")

	verify := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, ok := GetAccessKey(r.Context())
		require.True(t, ok)
		require.Equal(t, "AccessKey", key)
		require.Nil(t, r.MultipartForm)
		err = r.ParseMultipartForm(4096)
		require.NoError(t, err)
		require.Equal(t, "AccessKey", r.MultipartForm.Value["AWSAccessKeyId"][0])
		require.Equal(t, "Signature", r.MultipartForm.Value["Signature"][0])
	})

	AccessKey(verify).ServeHTTP(nil, req)
}
