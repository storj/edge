// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"context"
	"fmt"
	"net/http"

	"github.com/spacemonkeygo/monkit/v3"
)

const (
	// XStorjRequestID is the response request id.
	XStorjRequestID = "X-Storj-Request-Id"
)

// AddRequestIds uses XStorjRequestId field to set unique request Ids
// in the response headers for each request of auth and linksharing service, if it dosen't alreasy exist

func AddRequestIds(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Storing calling service requestId as ParentRequestID for auth service
		ctx := r.Context()
		if w.Header().Get(XStorjRequestID) == "" {
			trace := monkit.NewTrace(monkit.NewId())
			requestID := fmt.Sprintf("%x", trace.Id())
			w.Header().Set(XStorjRequestID, requestID)
			ctx = context.WithValue(ctx, XStorjRequestID, requestID)
		}

		h.ServeHTTP(w, r.WithContext(ctx))
	})
}
