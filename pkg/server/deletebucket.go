// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"context"
	"net/http"

	"github.com/gorilla/mux"

	"storj.io/uplink"
)

// DeleteBucket https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucket.html
func (s *Server) DeleteBucket(w http.ResponseWriter, r *http.Request) {
	s.WithProject(w, r, func(ctx context.Context, p *uplink.Project) error {
		bucket := mux.Vars(r)["bucket"]
		_, err := p.DeleteBucket(ctx, bucket)
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNoContent)
		return nil
	})
}
