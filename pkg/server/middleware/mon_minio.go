// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"net/http"

	"github.com/gorilla/mux"
)

// handlerNames must be kept in sync with minio.GlobalHandlers.
var handlerNames = []string{"filterReservedMetadata", "setSSETLSHandler", "setAuthHandler",
	"setTimeValidityHandler", "setBrowserCacheControlHandler", "setReservedBucketHandler",
	"setBrowserRedirectHandler", "setCrossDomainPolicy", "setRequestHeaderSizeLimitHandler",
	"setRequestSizeLimitHandler", "setHTTPStatsHandler", "setRequestValidityHandler",
	"setBucketForwardingHandler", "addSecurityHeaders", "addCustomHeaders", "setRedirectHandler",
}

// MonitorMinioGlobalHandler adds monkit metrics atop minio middlewares.
func MonitorMinioGlobalHandler(i int, f mux.MiddlewareFunc) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			defer mon.TaskNamed(handlerNames[i])(&ctx)(nil)
			f(next).ServeHTTP(w, r)
		})
	}
}
