// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package pkgmiddleware

import (
	"context"
	"fmt"
	"net/http"

	"github.com/spacemonkeygo/monkit/v3"
)

// Key to use when setting the request ID.
type ctxKeyRequestID string

const (
	// XStorjRequestID is the header key for the request ID.
	XStorjRequestID = "X-Storj-Request-Id"

	// RequestIDKey is the key that holds the unique request ID in a request context.
	RequestIDKey ctxKeyRequestID = "request-id"
)

// AddRequestIds uses XStorjRequestId field to set unique request Ids
// in the response headers for each request of auth and linksharing service, if it dosen't alreasy exist

func AddRequestIds(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if w.Header().Get(XStorjRequestID) == "" {
			trace := monkit.NewTrace(monkit.NewId())
			requestID := fmt.Sprintf("%x", trace.Id())
			w.Header().Set(XStorjRequestID, requestID)
			ctx = context.WithValue(ctx, RequestIDKey, requestID)
		}

		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetReqID returns the request ID from the context.
func GetReqID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if reqID, ok := ctx.Value(RequestIDKey).(string); ok {
		return reqID
	}
	return ""
}

// AddRequestIdHeader adds the request ID from the context to the response header.
func AddReqIdHeader(ctx context.Context, resp *http.Response) {
	// Ideally, the context should always have request ID, since it is being set in the middleware.
	resp.Header.Set(XStorjRequestID, GetReqID(ctx))
}
