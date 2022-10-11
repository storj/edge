// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"fmt"
	"net/http"

	"github.com/spacemonkeygo/monkit/v3"

	xhttp "storj.io/minio/cmd/http"
)

const (
	// XStorjRequestID is the response request id.
	XStorjRequestID = "X-Storj-Request-Id"
	// XStorjParentRequestID is the parent request Id for auth service.
	XStorjParentRequestID = "X-Storj-Parent-Request-Id"
)

// AddRequestIds uses XStorjRequestId field to set unique request Ids
// in the response headers for each request of auth and linksharing service.
// It also mantains calling service request Id in the XStorjParentRequestId field in auth service response header.
func AddRequestIds(service string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Storing calling service requestId as ParentRequestID for auth service
		if service == "auth" {
			if w.Header().Get(XStorjRequestID) != "" {
				w.Header().Set(XStorjParentRequestID, w.Header().Get(XStorjRequestID))
			} else if w.Header().Get(xhttp.AmzRequestID) != "" {
				w.Header().Set(XStorjParentRequestID, w.Header().Get(xhttp.AmzRequestID))
			} else {
				w.Header().Set(XStorjParentRequestID, "")
			}
		}

		trace := monkit.NewTrace(monkit.NewId())
		w.Header().Set(XStorjRequestID, fmt.Sprintf("%x", trace.Id()))
		h.ServeHTTP(w, r)
	})
}
