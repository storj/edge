// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package pkgmiddleware

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"storj.io/common/testcontext"
)

func TestAddRequestIDLinksharing(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	request, err := http.NewRequestWithContext(ctx, "GET", "", http.NoBody)
	require.NoError(t, err)

	rw := httptest.NewRecorder()
	var reqContext context.Context = nil

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		reqContext = r.Context()
	})

	newHandler := AddRequestID(handler)
	newHandler.ServeHTTP(rw, request)

	require.NotEqual(t, "", rw.Header().Get(XStorjRequestID), "RequestId value is not set")
	require.NotNil(t, "", reqContext.Value(RequestIDKey), "RequestId should not be nil")
	require.NotEqual(t, "", reqContext.Value(RequestIDKey).(string), "RequestId not set in Context")
}

func TestAddRequestIDAuth(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	requestID := "test-request-id"
	reqctx := context.WithValue(ctx, RequestIDKey, requestID)

	responseRecorder := httptest.NewRecorder()
	response := responseRecorder.Result()
	AddReqIDHeader(reqctx, response)

	fmt.Printf("\n\nRequest ID: %s", response.Header.Get(XStorjRequestID))

	require.Equal(t, requestID, response.Header.Get(XStorjRequestID), "RequestID value is not set")
	require.NotNil(t, reqctx.Value(RequestIDKey))
	require.Equal(t, requestID, reqctx.Value(RequestIDKey).(string), "RequestID not set in Context")
}
