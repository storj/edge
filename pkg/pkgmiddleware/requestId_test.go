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

func TestAddRequestIdsOnLinksharing(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	request, err := http.NewRequestWithContext(ctx, "GET", "", nil)
	require.NoError(t, err)

	rw := httptest.NewRecorder()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)

	})

	newHandler := AddRequestIds(handler)
	newHandler.ServeHTTP(rw, request)

	require.NotEqual(t, "", rw.Header().Get(XStorjRequestID), "RequestId value is not set")
	require.NotEqual(t, "", ctx.Value(RequestIDKey).(string), "RequestId not set in Context")
}

func TestAddRequestIdsOnAuth(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	requestID := "test-request-id"
	reqctx := context.WithValue(ctx, RequestIDKey, requestID)

	responseRecorder := httptest.NewRecorder()
	response := responseRecorder.Result()
	AddReqIdHeader(reqctx, response)

	fmt.Printf("\n\nRequest ID: %s", response.Header.Get(XStorjRequestID))

	require.Equal(t, requestID, response.Header.Get(XStorjRequestID), "RequestId value is not set")
	require.NotNil(t, reqctx.Value(RequestIDKey))
	require.Equal(t, requestID, reqctx.Value(RequestIDKey).(string), "RequestId not set in Context")
}
