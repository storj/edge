// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	xhttp "github.com/storj/minio/cmd/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"storj.io/common/testcontext"
	"storj.io/gateway-mt/pkg/server/gwlog"
)

func TestResponse(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	handler := func() http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "", nil)
	assert.NoError(t, err)
	rr := httptest.NewRecorder()

	observedZapCore, observedLogs := observer.New(zap.InfoLevel)
	observedLogger := zap.New(observedZapCore)

	LogResponsesNoPaths(observedLogger, handler()).ServeHTTP(rr, req)

	filteredLogs := observedLogs.FilterField(zap.Int("code", http.StatusOK))
	require.Len(t, filteredLogs.All(), 1)
}

func TestGatewayResponse(t *testing.T) {
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

	req, err := http.NewRequestWithContext(ctx, "GET", "", nil)
	require.NoError(t, err)
	rr := httptest.NewRecorder()

	observedZapCore, observedLogs := observer.New(zap.InfoLevel)
	observedLogger := zap.New(observedZapCore)

	LogResponsesNoPaths(observedLogger, handler()).ServeHTTP(rr, req)

	filteredLogs := observedLogs.FilterField(zap.String("error", "error!"))
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

		var query string
		if test.query != "" {
			query = fmt.Sprintf("?%s=test", test.query)
		}

		req, err := http.NewRequestWithContext(ctx, "GET", query, nil)
		require.NoError(t, err, i)

		if test.header != "" {
			req.Header.Add(test.header, "test")
		}

		rr := httptest.NewRecorder()

		observedZapCore, observedLogs := observer.New(zap.InfoLevel)
		observedLogger := zap.New(observedZapCore)

		LogResponsesNoPaths(observedLogger, handler()).ServeHTTP(rr, req)

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
