// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"net/http"

	"go.uber.org/zap"
)

// GetBucketVersioning returns the versioning state of a bucket.
func (s *Server) GetBucketVersioning(w http.ResponseWriter, r *http.Request) {
	s.log.Debug("GetBucketVersioning")
	// todo:  consider if <Status>Suspended</Status> is better
	_, err := w.Write([]byte(`<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>`))
	if err != nil {
		s.log.Error("GetBucketVersioning", zap.Error(err))
	}
}
