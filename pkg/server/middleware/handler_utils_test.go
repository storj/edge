// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"storj.io/common/testcontext"
)

func TestAddRequestIdsOnLinksharing(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	request, err := http.NewRequestWithContext(ctx, "GET", "", nil)
	require.NoError(t, err)

	rw := httptest.NewRecorder()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)

	})

	newHandler := AddRequestIds("linksharing", handler)
	newHandler.ServeHTTP(rw, request)

	require.NotEqual(t, "", rw.Header().Get("X-Storj-Request-Id"), "RequestId value is not set")
}

func TestAddRequestIdsOnAuth(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	request, err := http.NewRequestWithContext(ctx, "GET", "", nil)
	require.NoError(t, err)

	rw := httptest.NewRecorder()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)

	})

	newHandler := AddRequestIds("auth", handler)
	newHandler.ServeHTTP(rw, request)

	require.NotEqual(t, "", rw.Header().Get("X-Storj-Request-Id"), "RequestId value is not set")
	require.Equal(t, "", rw.Header().Get("X-Storj-Parent-Request-Id"), "ParentRequestId value is incorrect")
}
