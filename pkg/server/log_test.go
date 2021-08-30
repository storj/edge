// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	xhttp "github.com/minio/minio/cmd/http"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"storj.io/common/testcontext"
	"storj.io/gateway-mt/pkg/server/gwlog"
)

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

	observedZapCore, observedLogs := observer.New(zap.InfoLevel)
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

	observedZapCore, observedLogs := observer.New(zap.InfoLevel)
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

	observedZapCore, observedLogs := observer.New(zap.InfoLevel)
	observedLogger := zap.New(observedZapCore)

	LogResponses(observedLogger, handler(), false).ServeHTTP(rr, req)

	filteredLogs := observedLogs.FilterField(zap.String(requestURILogField, "/"))
	require.Len(t, filteredLogs.All(), 0)

	filteredLogs = observedLogs.FilterField(zap.String("error", "error!"))
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

	observedZapCore, observedLogs := observer.New(zap.InfoLevel)
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
		{header: xhttp.Authorization, query: ""},
		{header: "Cookie", query: ""},
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

		observedZapCore, observedLogs := observer.New(zap.InfoLevel)
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
