// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"storj.io/common/testcontext"
	"storj.io/gateway-mt/pkg/authclient"
	"storj.io/gateway-mt/pkg/trustedip"
	"storj.io/minio/cmd"
)

func TestParseV4Credentials(t *testing.T) {
	cred, err := ParseV4Credential("AccessKey/20000101/us-west-2/s3/aws4_request")
	require.NoError(t, err)
	require.Equal(t, &V4Credential{
		AccessKeyID: "AccessKey",
		Date:        time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		Region:      "us-west-2",
		Service:     "s3",
	}, cred)

	cred, err = ParseV4Credential("AccessKey/20000101//s3/aws4_request")
	require.NoError(t, err)
	require.Equal(t, &V4Credential{
		AccessKeyID: "AccessKey",
		Date:        time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		Region:      "",
		Service:     "s3",
	}, cred)

	_, err = ParseV4Credential("/20000101/us-west-2/s3/aws4_request")
	require.Error(t, err)

	_, err = ParseV4Credential("AccessKey//us-west-2/s3/aws4_request")
	require.Error(t, err)

	_, err = ParseV4Credential("AccessKey/20000101/us-west-2//aws4_request")
	require.Error(t, err)

	_, err = ParseV4Credential("")
	require.Error(t, err)

	_, err = ParseV4Credential("////")
	require.Error(t, err)

	_, err = ParseV4Credential("AccessKey/abcd124/us-west-2/s3/aws4_request")
	require.Error(t, err)
}

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

func TestAuthResponseErrorLogging(t *testing.T) {
	tests := []struct {
		desc           string
		status         int
		expectedMetric string
		expectedLevel  zapcore.Level
	}{
		{
			desc:           "authservice 400 response logs to debug level",
			status:         http.StatusBadRequest,
			expectedMetric: "gmt_authservice_error",
			expectedLevel:  zap.DebugLevel,
		},
		{
			desc:           "authservice 401 response logs to debug level",
			status:         http.StatusUnauthorized,
			expectedMetric: "gmt_authservice_error",
			expectedLevel:  zap.DebugLevel,
		},
		{
			desc:           "authservice unmapped response logs to error level",
			status:         http.StatusTeapot,
			expectedMetric: "gmt_unmapped_error",
			expectedLevel:  zap.ErrorLevel,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			ctx := testcontext.New(t)
			defer ctx.Cleanup()

			req, err := http.NewRequestWithContext(ctx, "GET", "", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=test/20211026/us-east-1/s3/aws4_request, Signature=test")
			req.Header.Set("X-Amz-Date", "20211026T233405Z")

			authService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
			}))
			defer authService.Close()

			observedZapCore, observedLogs := observer.New(zap.DebugLevel)
			observedLogger := zap.New(observedZapCore)

			verify := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				creds := GetAccess(r.Context())
				require.NotNil(t, creds)
				require.Equal(t, "", creds.AccessGrant)
				require.Equal(t, "", creds.SecretKey)
				require.Error(t, creds.Error)
			})

			authClient := authclient.New(authclient.Config{BaseURL: authService.URL, Token: "token", Timeout: 5 * time.Second})
			AccessKey(authClient, trustedip.NewListTrustAll(), observedLogger)(verify).ServeHTTP(nil, req)

			filteredLogs := observedLogs.FilterField(zap.String("error", fmt.Sprintf("auth service: invalid status code: %d", tc.status)))
			require.Len(t, filteredLogs.All(), 1)
			require.Equal(t, tc.expectedLevel, filteredLogs.All()[0].Level)
		})
	}
}

func TestAuthParseResponse(t *testing.T) {
	tests := []struct {
		desc                string
		method              string
		header              http.Header
		body                string
		url                 string
		authVersion         string
		authType            string
		expectedAccessKey   string
		expectedErrorCode   string
		expectedErrorStatus int
		expectedCount       float64
	}{
		{
			desc:        "not a v2 query request",
			url:         "?something=123",
			authVersion: "2",
			authType:    "query",
		},
		{
			desc:              "not a v2 header request",
			url:               "?AWSAccessKeyId=123&Signature=123",
			authVersion:       "2",
			authType:          "header",
			expectedAccessKey: "123",
		},
		{
			desc:              "v2 query request",
			url:               "?AWSAccessKeyId=123&Signature=123",
			authVersion:       "2",
			authType:          "query",
			expectedAccessKey: "123",
			expectedCount:     1.0,
		},
		{
			desc:                "empty key v2 query request",
			url:                 "?AWSAccessKeyId=&Signature=123",
			authVersion:         "2",
			authType:            "query",
			expectedErrorCode:   "AuthorizationQueryParametersError",
			expectedErrorStatus: http.StatusBadRequest,
		},
		{
			desc:                "missing fields v2 query request",
			url:                 "?AWSAccessKeyId=123",
			authVersion:         "2",
			authType:            "query",
			expectedErrorCode:   "AuthorizationQueryParametersError",
			expectedErrorStatus: http.StatusBadRequest,
		},
		{
			desc: "v2 header request",
			header: http.Header{
				"Authorization": {"AWS test:123"},
			},
			authVersion:       "2",
			authType:          "header",
			expectedAccessKey: "test",
			expectedCount:     1.0,
		},
		{
			desc: "invalid v2 header request",
			header: http.Header{
				"Authorization": {"AWS test"},
			},
			authVersion:         "2",
			authType:            "header",
			expectedErrorCode:   "InvalidArgument",
			expectedErrorStatus: http.StatusBadRequest,
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
			authVersion:       "2",
			authType:          "multipart",
			expectedAccessKey: "AccessKey",
			expectedCount:     1.0,
		},
		{
			desc:   "missing fields v2 multipart request",
			method: http.MethodPost,
			header: http.Header{
				"Content-Type": {"multipart/form-data; boundary=---------------------------9051914041544843365972754266"},
			},
			body: `-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="AWSAccessKeyId"

AccessKey
-----------------------------9051914041544843365972754266--`,
			authVersion:         "2",
			authType:            "multipart",
			expectedErrorCode:   "MissingFields",
			expectedErrorStatus: http.StatusBadRequest,
		},
		{
			desc:              "v4 query request",
			url:               "?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=123/20130524/us-east-1/s3/aws4_request&X-Amz-Signature=123&X-Amz-Content-SHA256=123&X-Amz-Date=20060102T150405Z",
			authVersion:       "4",
			authType:          "query",
			expectedAccessKey: "123",
			expectedCount:     1.0,
		},
		{
			desc:              "no region v4 query request",
			url:               "?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=123/20130524//s3/aws4_request&X-Amz-Signature=123&X-Amz-Content-SHA256=123&X-Amz-Date=20060102T150405Z",
			authVersion:       "4",
			authType:          "query",
			expectedAccessKey: "123",
			expectedCount:     1.0,
		},
		{
			desc:                "missing fields v4 query request",
			url:                 "?X-Amz-Credential=123/20130524/us-east-1/s3/aws4_request",
			authVersion:         "4",
			authType:            "query",
			expectedErrorCode:   "AuthorizationQueryParametersError",
			expectedErrorStatus: http.StatusBadRequest,
		},
		{
			desc:                "invalid credential v4 query request",
			url:                 "?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=123/abc123/us-east-1/s3/aws4_request&X-Amz-Signature=123&X-Amz-Content-SHA256=123&X-Amz-Date=20060102T150405Z",
			authVersion:         "4",
			authType:            "query",
			expectedErrorCode:   "AuthorizationQueryParametersError",
			expectedErrorStatus: http.StatusBadRequest,
		},
		{
			desc:                "missing credential fields v4 query request",
			url:                 "?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=123/abc123/us-east-1&X-Amz-Signature=123&X-Amz-Content-SHA256=123&X-Amz-Date=20060102T150405Z",
			authVersion:         "4",
			authType:            "query",
			expectedErrorCode:   "AuthorizationQueryParametersError",
			expectedErrorStatus: http.StatusBadRequest,
		},
		{
			desc:                "invalid date v4 query request",
			url:                 "?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=123/20130524/us-east-1/s3/aws4_request&X-Amz-Signature=123&X-Amz-Content-SHA256=123&X-Amz-Date=abc123",
			authVersion:         "4",
			authType:            "query",
			expectedErrorCode:   "AuthorizationQueryParametersError",
			expectedErrorStatus: http.StatusBadRequest,
		},
		{
			desc:                "invalid algorithm v4 query request",
			url:                 "?X-Amz-Algorithm=abc123&X-Amz-Credential=123/20130524/us-east-1/s3/aws4_request&X-Amz-Signature=123&X-Amz-Content-SHA256=123&X-Amz-Date=20060102T150405Z",
			authVersion:         "4",
			authType:            "query",
			expectedErrorCode:   "AuthorizationQueryParametersError",
			expectedErrorStatus: http.StatusBadRequest,
		},
		{
			desc: "v4 header request",
			header: http.Header{
				"Authorization": {"AWS4-HMAC-SHA256 Credential=123/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-date,Signature=123"},
				"X-Amz-Date":    {"20060102T150405Z"},
			},
			authVersion:       "4",
			authType:          "header",
			expectedAccessKey: "123",
			expectedCount:     1.0,
		},
		{
			desc: "no region v4 header request",
			header: http.Header{
				"Authorization": {"AWS4-HMAC-SHA256 Credential=123/20130524//s3/aws4_request,SignedHeaders=host;range;x-amz-date,Signature=123"},
				"X-Amz-Date":    {"20060102T150405Z"},
			},
			authVersion:       "4",
			authType:          "header",
			expectedAccessKey: "123",
			expectedCount:     1.0,
		},
		{
			desc: "missing fields v4 header request",
			header: http.Header{
				"Authorization": {"AWS4-HMAC-SHA256 Credential=123/20130524//s3/aws4_request"},
			},
			authVersion:         "4",
			authType:            "header",
			expectedErrorCode:   "AccessDenied",
			expectedErrorStatus: http.StatusForbidden,
		},
		{
			desc: "missing credential fields v4 header request",
			header: http.Header{
				"Authorization": {"AWS4-HMAC-SHA256 Credential=123/20130524/us-east-1,SignedHeaders=host;range;x-amz-date,Signature=123"},
				"X-Amz-Date":    {"20060102T150405Z"},
			},
			authVersion:         "4",
			authType:            "header",
			expectedErrorCode:   "AuthorizationQueryParametersError",
			expectedErrorStatus: http.StatusBadRequest,
		},
		{
			desc: "invalid credential date v4 header request",
			header: http.Header{
				"Authorization": {"AWS4-HMAC-SHA256 Credential=123/abc123/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-date,Signature=123"},
				"X-Amz-Date":    {"20060102T150405Z"},
			},
			authVersion:         "4",
			authType:            "header",
			expectedErrorCode:   "AuthorizationQueryParametersError",
			expectedErrorStatus: http.StatusBadRequest,
		},
		{
			desc: "invalid date header v4 header request",
			header: http.Header{
				"Authorization": {"AWS4-HMAC-SHA256 Credential=123/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-date,Signature=123"},
				"X-Amz-Date":    {"abc123"},
			},
			authVersion:         "4",
			authType:            "header",
			expectedErrorCode:   "AccessDenied",
			expectedErrorStatus: http.StatusForbidden,
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
			authVersion:       "4",
			authType:          "multipart",
			expectedAccessKey: "AccessKey",
			expectedCount:     1.0,
		},
		{
			desc:   "missing fields v4 multipart request",
			method: http.MethodPost,
			header: http.Header{
				"Content-Type": {"multipart/form-data; boundary=---------------------------9051914041544843365972754266"},
			},
			body: `-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="X-Amz-Signature"

X-Amz-Signature
-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="X-Amz-Credential"

AccessKey/20000101/region/s3/aws4_request
-----------------------------9051914041544843365972754266--`,
			authVersion:         "4",
			authType:            "multipart",
			expectedErrorCode:   "MissingFields",
			expectedErrorStatus: http.StatusBadRequest,
		},
		{
			desc:   "invalid credential v4 multipart request",
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

AccessKey/20000101/region/s3
-----------------------------9051914041544843365972754266--`,
			authVersion:         "4",
			authType:            "multipart",
			expectedErrorCode:   "AuthorizationQueryParametersError",
			expectedErrorStatus: http.StatusBadRequest,
		},
		{
			desc:   "malformed POST data multipart request",
			method: http.MethodPost,
			header: http.Header{
				"Content-Type": {"multipart/form-data; boundary=abc123"},
			},
			body:                "------abc123",
			expectedErrorCode:   "MalformedPOSTRequest",
			expectedErrorStatus: http.StatusBadRequest,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			ctx := testcontext.New(t)
			defer ctx.Cleanup()

			req, err := http.NewRequestWithContext(ctx, tc.method, tc.url, strings.NewReader(tc.body))
			require.NoError(t, err)
			rr := httptest.NewRecorder()

			req.Header = tc.header

			authService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err := w.Write([]byte(`{"public":true, "secret_key":"SecretKey", "access_grant":"AccessGrant"}`))
				require.NoError(t, err)
			}))
			defer authService.Close()

			authClient := authclient.New(authclient.Config{BaseURL: authService.URL, Token: "token", Timeout: 5 * time.Second})

			metricKey := fmt.Sprintf("auth,scope=storj.io/gateway-mt/pkg/server/middleware,type=%s,version=%s value", tc.authType, tc.authVersion)
			c := monkit.Collect(monkit.ScopeNamed("storj.io/gateway-mt/pkg/server/middleware"))
			initialCount := c[metricKey]

			AccessKey(authClient, trustedip.NewListTrustAll(), zap.L())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				creds := GetAccess(r.Context())
				if tc.expectedAccessKey == "" {
					require.Nil(t, creds)
				} else {
					require.NotNil(t, creds)
					require.Equal(t, tc.expectedAccessKey, creds.AccessKey)
				}
			})).ServeHTTP(rr, req)

			if tc.expectedErrorCode != "" {
				var apiErr cmd.APIError
				require.NoError(t, xml.NewDecoder(rr.Body).Decode(&apiErr))
				require.Equal(t, tc.expectedErrorCode, apiErr.Code)
			}
			if tc.expectedErrorStatus != 0 {
				require.Equal(t, tc.expectedErrorStatus, rr.Code)
			}

			c = monkit.Collect(monkit.ScopeNamed("storj.io/gateway-mt/pkg/server/middleware"))
			require.Equal(t, initialCount+tc.expectedCount, c[metricKey])
		})
	}
}
