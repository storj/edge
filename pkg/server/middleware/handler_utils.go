// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"fmt"
	"net/http"

	"github.com/spacemonkeygo/monkit/v3"
	xhttp "storj.io/minio/cmd/http"
)

// Uses the field XStorjRequestId to set unique request Ids in the response headers for each request.
func AddRequestIds(service string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		//Storing calling service requestId as ParentRequestID for auth service
		if service == "auth" {
			if w.Header().Get("X-Storj-Request-Id") != "" {
				w.Header().Set(xhttp.XStorjParentRequestId, w.Header().Get("X-Storj-Request-Id"))
			} else if w.Header().Get("x-amz-request-id") != "" {
				w.Header().Set(xhttp.XStorjParentRequestId, w.Header().Get("x-amz-request-id"))
			} else {
				w.Header().Set(xhttp.XStorjParentRequestId, "")
			}

		}

		trace := monkit.NewTrace(monkit.NewId())
		w.Header().Set(xhttp.XStorjRequestId, fmt.Sprintf("%x", trace.Id()))
		//zap.S().Info("ParentRequestIs: %s and RequestId: %s", xhttp.XStorjParentRequestId, xhttp.XStorjRequestId)
		h.ServeHTTP(w, r)

	})
}
