// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package handlers

import (
	"io/fs"
	"net/http"
)

// NewStaticHandler creates a handler for static asset requests.
func NewStaticHandler(assets fs.FS, dynamic bool) (http.Handler, error) {
	fs, err := fs.Sub(assets, "static")
	if err != nil {
		return nil, err
	}
	handler := http.StripPrefix("/static/", http.FileServer(http.FS(fs)))
	if !dynamic {
		return cacheControlStaticHandler(handler), nil
	}
	return handler, nil
}

func cacheControlStaticHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=15552000")
		h.ServeHTTP(w, r)
	})
}
