// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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

	authClient := authclient.New(authclient.Config{BaseURL: authService.URL, Token: "token", Timeout: 5 * time.Second})
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

	authClient := authclient.New(authclient.Config{BaseURL: authService.URL, Token: "token", Timeout: 5 * time.Second})
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

func TestAuthTypeMetrics(t *testing.T) {
	tests := []struct {
		desc          string
		method        string
		header        http.Header
		body          string
		url           string
		authVersion   string
		authType      string
		expectedCount float64
	}{
		{
			desc:          "not a v2 query request",
			url:           "?something=123",
			authVersion:   "2",
			authType:      "query",
			expectedCount: 0.0,
		},
		{
			desc:          "not a v2 header request",
			url:           "?AWSAccessKeyId=123&Signature=123",
			authVersion:   "2",
			authType:      "header",
			expectedCount: 0.0,
		},
		{
			desc:          "v2 query request",
			url:           "?AWSAccessKeyId=123&Signature=123",
			authVersion:   "2",
			authType:      "query",
			expectedCount: 1.0,
		},
		{
			desc: "v2 header request",
			header: http.Header{
				"Authorization": {"AWS test:123"},
			},
			authVersion:   "2",
			authType:      "header",
			expectedCount: 1.0,
		},
		{
			desc:   "v2 multipart request",
			method: http.MethodPost,
			header: http.Header{
				"Content-Type": {"multipart/form-data; boundary=---------------------------9051914041544843365972754266"},
			},
			body: `-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="Signature"

Signature
-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="AWSAccessKeyId"

AccessKey
-----------------------------9051914041544843365972754266--`,
			authVersion:   "2",
			authType:      "multipart",
			expectedCount: 1.0,
		},
		{
			desc:          "v4 query request",
			url:           "?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=123/20130524/us-east-1/s3/aws4_request&X-Amz-Signature=123&X-Amz-Content-SHA256=123&X-Amz-Date=20060102T150405Z",
			authVersion:   "4",
			authType:      "query",
			expectedCount: 1.0,
		},
		{
			desc: "v4 header request",
			header: http.Header{
				"Authorization": {"AWS4-HMAC-SHA256 Credential=123/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-date,Signature=123"},
				"X-Amz-Date":    {"20060102T150405Z"},
			},
			authVersion:   "4",
			authType:      "header",
			expectedCount: 1.0,
		},
		{
			desc:   "v4 multipart request",
			method: http.MethodPost,
			header: http.Header{
				"Content-Type": {"multipart/form-data; boundary=---------------------------9051914041544843365972754266"},
			},
			body: `-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="X-Amz-Signature"

X-Amz-Signature
-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="X-Amz-Date"

20060102T150405Z
-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="X-Amz-Credential"

AccessKey/20000101/region/s3/aws4_request
-----------------------------9051914041544843365972754266--`,
			authVersion:   "4",
			authType:      "multipart",
			expectedCount: 1.0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			ctx := testcontext.New(t)
			defer ctx.Cleanup()

			req, err := http.NewRequestWithContext(ctx, tc.method, tc.url, strings.NewReader(tc.body))
			require.NoError(t, err)

			req.Header = tc.header

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// no-op
			})
			authService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err := w.Write([]byte(`{"public":true, "secret_key":"SecretKey", "access_grant":"AccessGrant"}`))
				require.NoError(t, err)
			}))
			defer authService.Close()

			authClient := authclient.New(authclient.Config{BaseURL: authService.URL, Token: "token", Timeout: 5 * time.Second})

			metricKey := fmt.Sprintf("auth,scope=storj.io/gateway-mt/pkg/server/middleware,type=%s,version=%s value", tc.authType, tc.authVersion)
			c := monkit.Collect(monkit.ScopeNamed("storj.io/gateway-mt/pkg/server/middleware"))
			initialCount := c[metricKey]

			AccessKey(authClient, trustedip.NewListTrustAll(), zap.L())(handler).ServeHTTP(nil, req)

			c = monkit.Collect(monkit.ScopeNamed("storj.io/gateway-mt/pkg/server/middleware"))
			require.Equal(t, initialCount+tc.expectedCount, c[metricKey])
		})
	}
}
