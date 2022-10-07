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
	// Response request id and Parent request Id (only used for auth service)
	XStorjRequestId       = "X-Storj-Request-Id"
	XStorjParentRequestId = "X-Storj-Parent-Request-Id"
)

// AddRequestIds uses XStorjRequestId field to set unique request Ids,
// in the response headers for each request of auth and linksharing service.
// It also mantains calling service request Id in the XStorjParentRequestId field in auth service response header.
func AddRequestIds(service string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Storing calling service requestId as ParentRequestID for auth service
		if service == "auth" {
			if w.Header().Get(XStorjRequestId) != "" {
				w.Header().Set(XStorjParentRequestId, w.Header().Get(XStorjRequestId))
			} else if w.Header().Get(xhttp.AmzRequestID) != "" {
				w.Header().Set(XStorjParentRequestId, w.Header().Get(xhttp.AmzRequestID))
			} else {
				w.Header().Set(XStorjParentRequestId, "")
			}

		}

		trace := monkit.NewTrace(monkit.NewId())
		w.Header().Set(XStorjRequestId, fmt.Sprintf("%x", trace.Id()))
		h.ServeHTTP(w, r)

	})
}
