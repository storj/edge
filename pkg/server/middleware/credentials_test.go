// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"storj.io/common/testcontext"
	"storj.io/gateway-mt/pkg/authclient"
	"storj.io/gateway-mt/pkg/trustedip"
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

	// mock the auth service
	authService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/access/AccessKey", r.URL.Path)
		_, err := w.Write([]byte(`{"public":true, "secret_key":"SecretKey", "access_grant":"AccessGrant"}`))
		require.NoError(t, err)
	}))
	defer authService.Close()

	// validate the auth middleware, including that the multipart form can be read from afterwards
	verify := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		access := GetAccess(r.Context())
		require.NotNil(t, access)
		require.Equal(t, "AccessKey", access.AccessKey)
		require.Equal(t, "SecretKey", access.SecretKey)
		require.Equal(t, "AccessGrant", access.AccessGrant)
		require.Nil(t, r.MultipartForm)
		err = r.ParseMultipartForm(4096)
		require.NoError(t, err)
		require.Equal(t, "20060102T150405Z", r.MultipartForm.Value["X-Amz-Date"][0])
		require.Equal(t, "AccessKey/20000101/region/s3/aws4_request", r.MultipartForm.Value["X-Amz-Credential"][0])
		require.Equal(t, "X-Amz-Signature", r.MultipartForm.Value["X-Amz-Signature"][0])
	})

	authURL, err := url.Parse(authService.URL)
	require.NoError(t, err)
	authClient, err := authclient.New(authURL, "token", 5*time.Second)
	require.NoError(t, err)
	AccessKey(authClient, trustedip.NewListTrustAll(), zap.L())(verify).ServeHTTP(nil, req)
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

	// mock the auth service
	authService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/access/AccessKey", r.URL.Path)
		_, err := w.Write([]byte(`{"public":true, "secret_key":"SecretKey", "access_grant":"AccessGrant"}`))
		require.NoError(t, err)
	}))
	defer authService.Close()

	// validate the auth middleware, including that the multipart form can be read from afterwards
	verify := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		access := GetAccess(r.Context())
		require.NotNil(t, access)
		require.Equal(t, "AccessKey", access.AccessKey)
		require.Equal(t, "SecretKey", access.SecretKey)
		require.Equal(t, "AccessGrant", access.AccessGrant)
		require.Nil(t, r.MultipartForm)
		err = r.ParseMultipartForm(4096)
		require.NoError(t, err)
		require.Equal(t, "AccessKey", r.MultipartForm.Value["AWSAccessKeyId"][0])
		require.Equal(t, "Signature", r.MultipartForm.Value["Signature"][0])
	})

	authURL, err := url.Parse(authService.URL)
	require.NoError(t, err)
	authClient, err := authclient.New(authURL, "token", 5*time.Second)
	require.NoError(t, err)
	AccessKey(authClient, trustedip.NewListTrustAll(), zap.L())(verify).ServeHTTP(nil, req)
}

func TestLogError(t *testing.T) {
	observedZapCore, observedLogs := observer.New(zap.InfoLevel)
	observedLogger := zap.New(observedZapCore)

	err := errors.New("Get \"http://localhost:8000/v1/access/12345\": dial tcp")
	logError(observedLogger, err)

	filteredLogs := observedLogs.FilterField(zap.String("error", "Get \"http://localhost:8000/v1[...]\": dial tcp"))
	require.Len(t, filteredLogs.All(), 1)

	c := monkit.Collect(monkit.ScopeNamed("storj.io/gateway-mt/pkg/server/middleware"))
	require.Equal(t, 1.0, c["gmt_unmapped_error,api=SYSTEM,error=Get\\ \"http://localhost:8000/v1[...]\":\\ dial\\ tcp,scope=storj.io/gateway-mt/pkg/server/middleware total"])
}
