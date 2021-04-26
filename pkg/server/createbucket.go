// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"context"
	"net/http"

	"github.com/gorilla/mux"

	"storj.io/uplink"
)

// CreateBucket https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html
func (s *Server) CreateBucket(w http.ResponseWriter, r *http.Request) {
	s.WithProject(w, r, func(ctx context.Context, p *uplink.Project) error {
		bucket := mux.Vars(r)["bucket"]
		_, err := p.CreateBucket(ctx, bucket)
		if err != nil {
			return err
		}

		w.Header().Set("Location", r.URL.Path)
		w.WriteHeader(http.StatusCreated)
		return nil
	})
}
