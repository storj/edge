// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"context"
	"fmt"
	"net/http"

	"github.com/spacemonkeygo/monkit/v3"
)

// RequestIDKey is the key that holds the unique request ID in a request context.
type RequestIDKey struct{}

const (
	// XStorjRequestID is the header key for the request ID.
	XStorjRequestID = "X-Storj-Request-Id"
)

// AddRequestID uses XStorjRequestId field to set unique request Ids
// in the response headers for each request of auth and linksharing service, if it dosen't alreasy exist.
func AddRequestID(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get(XStorjRequestID)
		if requestID == "" {
			requestID = fmt.Sprintf("%x", monkit.NewId())
		}

		w.Header().Set(XStorjRequestID, requestID)
		ctx := context.WithValue(r.Context(), RequestIDKey{}, requestID)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetReqID returns the request ID from the context.
func GetReqID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}

	if ctx.Value(RequestIDKey{}) == nil {
		return ""
	}

	if reqID, ok := ctx.Value(RequestIDKey{}).(string); ok {
		return reqID
	}
	return ""
}

// AddReqIDHeader adds the request ID from the context to the request header.
func AddReqIDHeader(req *http.Request) {
	if req == nil {
		return
	}

	// Ideally, the context should always have request ID, since it is being set in the middleware.
	req.Header.Set(XStorjRequestID, GetReqID(req.Context()))
}
