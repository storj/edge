// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import "net/http"

// Preflight sets CORS headers and ensures the correct HTTP method is used.
func Preflight(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodOptions:
			writeCORSHeaders(w)
			return
		case http.MethodHead, http.MethodGet:
			writeCORSHeaders(w)
			h.ServeHTTP(w, r)
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	})
}

func writeCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD")
	w.Header().Set("Access-Control-Allow-Headers", "*")
}
