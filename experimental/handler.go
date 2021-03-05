// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"net/http"

	"github.com/storj/minio/pkg/storj/router"
)

// Handler type
type Handler struct{}

// Get returns the a handler for the give type or nil if not implemented.
func (h *Handler) Get(t router.HandlerType) http.HandlerFunc {
	switch t {
	// Bucket APIs
	case router.ListBuckets:
		return h.ListBuckets
	case router.CreateBucket:
		return h.CreateBucket
	case router.HeadBucket:
		return h.HeadBucket
	case router.DeleteBucket:
		return h.DeleteBucket
	// Object APIs
	case router.ListObjects:
		return nil
	case router.ListObjectsV2:
		return nil
	case router.PutObject:
		return nil
	case router.HeadObject:
		return nil
	case router.GetObject:
		return nil
	case router.DeleteObject:
		return nil
	}

	// Return nil for all unknown handlers.
	return nil
}
