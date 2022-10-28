// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"storj.io/common/testcontext"
)

func TestAddRequestID(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	request, err := http.NewRequestWithContext(ctx, "GET", "", http.NoBody)
	require.NoError(t, err)

	rw := httptest.NewRecorder()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		require.NotNil(t, "", r.Context().Value(requestIDKey{}), "RequestId should not be nil")
		require.NotEqual(t, "", r.Context().Value(requestIDKey{}).(string), "RequestId not set in Context")
	})

	newHandler := AddRequestID(handler)
	newHandler.ServeHTTP(rw, request)

	require.NotEqual(t, "", rw.Header().Get(XStorjRequestID), "RequestId is not set in response header")
}

func TestAddRequestIDHeader(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	requestID := "test-request-id"
	reqctx := context.WithValue(ctx, requestIDKey{}, requestID)

	request, err := http.NewRequestWithContext(reqctx, "GET", "", http.NoBody)
	require.NoError(t, err)

	AddRequestIDToHeaders(request)

	require.Equal(t, requestID, request.Header.Get(XStorjRequestID), "RequestID value is not set")
}
