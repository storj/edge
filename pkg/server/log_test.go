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
	"storj.io/gateway-mt/pkg/gwlog"
)

func TestResponse(t *testing.T) {
	ctx := testcontext.New(t)

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

	handler := func() http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if log, ok := gwlog.FromContext(r.Context()); ok {
				log.RequestID = "ABC123"
				log.SetTags("error", "error!")
			}

			w.WriteHeader(http.StatusOK)
		})
	}

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("?%s=abc123", xhttp.AmzAccessKeyID), nil)
	req.Header.Add(xhttp.Authorization, "AWS4-HMAC-SHA256 Credential=123")
	require.NoError(t, err)
	rr := httptest.NewRecorder()

	observedZapCore, observedLogs := observer.New(zap.InfoLevel)
	observedLogger := zap.New(observedZapCore)

	LogResponsesNoPaths(observedLogger, handler()).ServeHTTP(rr, req)

	filteredLogs := observedLogs.FilterField(zap.String("error", "error!"))
	require.Len(t, filteredLogs.All(), 1)

	filteredLogs = observedLogs.FilterField(zap.String("request-id", "ABC123"))
	require.Len(t, filteredLogs.All(), 1)

	filteredLogs = observedLogs.FilterField(zap.Strings("query", []string{
		fmt.Sprintf("%s=[...]", xhttp.AmzAccessKeyID),
	}))
	require.Len(t, filteredLogs.All(), 1)

	filteredLogs = observedLogs.FilterField(zap.Strings("req-headers", []string{
		"Authorization=[...]",
	}))
	require.Len(t, filteredLogs.All(), 1)
}
