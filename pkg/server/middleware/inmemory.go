// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"net/http"

	"storj.io/common/fpath"
)

// SetInMemory sets appropriate context value for every request with information
// for uplink to perform in-memory segment encoding while uploading a file.
func SetInMemory(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(fpath.WithTempData(r.Context(), "", true)))
	})
}
