// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package handlers

import (
	"net/http"
	"sync/atomic"
)

// NewHealthCheckHandler creates a health check handler for health requests.
func NewHealthCheckHandler(inShutdown *int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(inShutdown) != 0 {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("okay"))
	})
}
