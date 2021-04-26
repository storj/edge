// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"context"
	"net/http"

	"github.com/gorilla/mux"

	"storj.io/uplink"
)

// HeadBucket https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadBucket.html
func (s *Server) HeadBucket(w http.ResponseWriter, r *http.Request) {
	s.WithProject(w, r, func(ctx context.Context, p *uplink.Project) error {
		bucket := mux.Vars(r)["bucket"]
		_, err := p.StatBucket(ctx, bucket)
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNoContent)
		return nil
	})
}
