// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"storj.io/common/testcontext"
	"storj.io/gateway-mt/pkg/authclient"
	"storj.io/gateway-mt/pkg/server/gwlog"
	"storj.io/gateway-mt/pkg/trustedip"
	xhttp "storj.io/minio/cmd/http"
)

const testAccessGrant = "13J4Upun87ATb3T5T5sDXVeQaCzWFZeF9Ly4ELfxS5hUwTL8APEkwahTEJ1wxZjyErimiDs3kgid33kDLuYPYtwaY7Toy32mCTapfrUB814X13RiA844HPWK3QLKZb9cAoVceTowmNZXWbcUMKNbkMHCURE4hn8ZrdHPE3S86yngjvDxwKmarfGx"

func TestResponseNoPaths(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	handler := func() http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	}

	req := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
	rr := httptest.NewRecorder()

	observedZapCore, observedLogs := observer.New(zap.DebugLevel)
	observedLogger := zap.New(observedZapCore)

	LogResponses(observedLogger, handler(), false).ServeHTTP(rr, req)

	filteredLogs := observedLogs.FilterField(zap.String(requestURILogField, "/"))
	require.Len(t, filteredLogs.All(), 0)

	filteredLogs = observedLogs.FilterField(zap.Int("code", http.StatusOK))
	require.Len(t, filteredLogs.All(), 1)
}

func TestResponsePathsIncluded(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	handler := func() http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	}

	req := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
	rr := httptest.NewRecorder()

	observedZapCore, observedLogs := observer.New(zap.DebugLevel)
	observedLogger := zap.New(observedZapCore)

	LogResponses(observedLogger, handler(), true).ServeHTTP(rr, req)

	filteredLogs := observedLogs.FilterField(zap.String(requestURILogField, "/"))
	require.Len(t, filteredLogs.All(), 1)
}

func TestGatewayResponseNoPaths(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	handler := func() http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if log, ok := gwlog.FromContext(r.Context()); ok {
				log.RequestID = "ABC123"
				log.SetTags("error", "error!")
			}

			w.WriteHeader(http.StatusOK)
		})
	}

	req := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
	rr := httptest.NewRecorder()

	observedZapCore, observedLogs := observer.New(zap.DebugLevel)
	observedLogger := zap.New(observedZapCore)

	LogResponses(observedLogger, handler(), false).ServeHTTP(rr, req)

	filteredLogs := observedLogs.FilterField(zap.String(requestURILogField, "/"))
	require.Len(t, filteredLogs.All(), 0)

	filteredLogs = observedLogs.FilterField(zap.String("error", "error!"))
	require.Len(t, filteredLogs.All(), 1)
}

func TestAccessDetailsLogged(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	handler := func() http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if log, ok := gwlog.FromContext(r.Context()); ok {
				log.RequestID = "ABC123"
			}

			w.WriteHeader(http.StatusOK)
		})
	}

	req := httptest.NewRequest("GET", "/test?q=123", nil).WithContext(ctx)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=jvvsakmsemhqns6g7ix7pinqlyuq/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-date,Signature=123")
	req.Header.Set("X-Amz-Date", "20060102T150405Z")
	rr := httptest.NewRecorder()

	observedZapCore, observedLogs := observer.New(zap.DebugLevel)
	observedLogger := zap.New(observedZapCore)

	authService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(fmt.Sprintf(`{"public":true,"secret_key":"SecretKey","access_grant":"%s"}`, testAccessGrant)))
		require.NoError(t, err)
	}))
	defer authService.Close()

	authClient := authclient.New(authclient.Config{BaseURL: authService.URL, Token: "token", Timeout: 5 * time.Second})

	AccessKey(authClient, trustedip.NewListTrustAll(), observedLogger)(LogResponses(observedLogger, handler(), true)).ServeHTTP(rr, req)

	filteredLogs := observedLogs.FilterField(zap.String("encryption-key-hash", "64f74892360a5cd203e9111d2ce72dd46ee195bf3dc33a2f0dddc892529b145d"))
	require.Len(t, filteredLogs.All(), 1)

	filteredLogs = observedLogs.FilterField(zap.String("macaroon-head", "4dff5d8e6b3506be68cf76b480ab1261ac391fe5a2f7db66d1293d68109f3665"))
	require.Len(t, filteredLogs.All(), 1)
}

func TestGatewayResponsePathsIncluded(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	handler := func() http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if log, ok := gwlog.FromContext(r.Context()); ok {
				log.RequestID = "ABC123"
			}

			w.WriteHeader(http.StatusOK)
		})
	}

	req := httptest.NewRequest("GET", "/test?q=123", nil).WithContext(ctx)
	rr := httptest.NewRecorder()

	observedZapCore, observedLogs := observer.New(zap.DebugLevel)
	observedLogger := zap.New(observedZapCore)

	LogResponses(observedLogger, handler(), true).ServeHTTP(rr, req)

	filteredLogs := observedLogs.FilterField(zap.String(requestURILogField, "/test?q=123"))
	require.Len(t, filteredLogs.All(), 1)
}

func TestGatewayLogsObfuscatedRequestMetadata(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	tests := []struct {
		header string
		query  string
	}{
		{query: xhttp.AmzAccessKeyID, header: ""},
		{query: xhttp.AmzSignatureV2, header: ""},
		{query: xhttp.AmzSignature, header: ""},
		{query: xhttp.AmzCredential, header: ""},
		{query: "prefix", header: ""},
		{header: xhttp.Authorization, query: ""},
		{header: "Cookie", query: ""},
		{header: xhttp.AmzCopySource, query: ""},
	}
	for i, test := range tests {
		handler := func() http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if log, ok := gwlog.FromContext(r.Context()); ok {
					log.RequestID = "ABC123"
				}
				w.WriteHeader(http.StatusOK)
			})
		}

		target := "/"
		if test.query != "" {
			target = fmt.Sprintf("/?%s=test", test.query)
		}

		req := httptest.NewRequest("GET", target, nil).WithContext(ctx)
		rr := httptest.NewRecorder()

		if test.header != "" {
			req.Header.Add(test.header, "test")
		}

		observedZapCore, observedLogs := observer.New(zap.DebugLevel)
		observedLogger := zap.New(observedZapCore)

		LogResponses(observedLogger, handler(), false).ServeHTTP(rr, req)

		var filteredLogs *observer.ObservedLogs

		if test.header != "" {
			filteredLogs = observedLogs.FilterField(zap.Strings("req-headers", []string{
				fmt.Sprintf("%s=[...]", test.header),
			}))
			require.Len(t, filteredLogs.All(), 1, i)
		}

		if test.query != "" {
			filteredLogs = observedLogs.FilterField(zap.Strings("query", []string{
				fmt.Sprintf("%s=[...]", test.query),
			}))
			require.Len(t, filteredLogs.All(), 1, i)
		}
	}
}

func TestRemoteIP(t *testing.T) {
	testCases := []struct {
		desc       string
		remoteAddr string
		header     http.Header
		expectedIP string
	}{
		{
			desc:       "RemoteAddr only",
			remoteAddr: "1.2.3.4",
			expectedIP: "1.2.3.4",
		},
		{
			desc:       "X-Forwarded-For, and RemoteAddr",
			remoteAddr: "1.2.3.4",
			header:     http.Header{"X-Forwarded-For": []string{"4.5.6.7"}},
			expectedIP: "4.5.6.7",
		},
		{
			desc:       "X-Real-Ip, and RemoteAddr",
			remoteAddr: "1.2.3.4",
			header:     http.Header{"X-Real-Ip": []string{"4.5.6.7"}},
			expectedIP: "4.5.6.7",
		},
		{
			desc:       "Forwarded, and RemoteAddr",
			remoteAddr: "1.2.3.4",
			header:     http.Header{"Forwarded": []string{"for=7.8.9.0"}},
			expectedIP: "7.8.9.0",
		},
		{
			desc:       "X-Forwarded-For, X-Real-Ip, and RemoteAddr",
			remoteAddr: "1.2.3.4",
			header: http.Header{
				"X-Forwarded-For": []string{"4.5.6.7"},
				"X-Real-Ip":       []string{"7.8.9.0"},
			},
			expectedIP: "4.5.6.7",
		},
		{
			desc:       "Forwarded, X-Forwarded-For, X-Real-Ip, and RemoteAddr",
			remoteAddr: "1.2.3.4",
			header: http.Header{
				"Forwarded":       []string{"for=4.3.2.1"},
				"X-Forwarded-For": []string{"4.5.6.7"},
				"X-Real-Ip":       []string{"7.8.9.0"},
			},
			expectedIP: "4.3.2.1",
		},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			ctx := testcontext.New(t)
			defer ctx.Cleanup()

			handler := func() http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				})
			}

			req := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
			req.RemoteAddr = tc.remoteAddr
			req.Header = tc.header

			rr := httptest.NewRecorder()

			observedZapCore, observedLogs := observer.New(zap.DebugLevel)
			observedLogger := zap.New(observedZapCore)

			LogResponses(observedLogger, handler(), true).ServeHTTP(rr, req)

			filteredLogs := observedLogs.FilterField(zap.String("remote-ip", tc.expectedIP))
			require.Len(t, filteredLogs.All(), 1)
		})
	}
}
