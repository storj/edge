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
	XStorjRequestId       = "X-Storj-Request-Id"
	XStorjParentRequestId = "X-Storj-Parent-Request-Id"
)

// Uses the field XStorjRequestId to set unique request Ids in the response headers for each request.
func AddRequestIds(service string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		//Storing calling service requestId as ParentRequestID for auth service
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
		//zap.S().Info("ParentRequestIs: %s and RequestId: %s", xhttp.XStorjParentRequestId, xhttp.XStorjRequestId)
		h.ServeHTTP(w, r)

	})
}
