// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"storj.io/common/errs2"
)

var (
	// Error is an error class for internal Multinode Dashboard http server error.
	Error = errs.Class("S3 compatible server error")
)

// Config contains configuration for an S3 compatible http server.
type Config struct {
	Address    string
	DomainName string
}

// Server represents an S3 compatible http server.
type Server struct {
	http     http.Server
	listener net.Listener
	log      *zap.Logger
}

// New returns new instance of an S3 compatible http server.
func New(listener net.Listener, log *zap.Logger, tlsConfig *tls.Config, config Config) (*Server, error) {
	r := mux.NewRouter()
	s := &Server{listener: listener, log: log, http: http.Server{Handler: r, Addr: config.Address}}

	if tlsConfig != nil {
		s.listener = tls.NewListener(listener, tlsConfig)
		s.http.TLSConfig = tlsConfig
	}

	pathStyle := r.Host(config.DomainName).Subrouter()
	s.AddRoutes(pathStyle, "/{bucket:.+}", "/{bucket:.+}/{key:.+}")
	pathStyle.HandleFunc("/", s.ListBuckets).Methods(http.MethodGet)

	virtualHostStyle := r.Host("{bucket:.+}." + config.DomainName).Subrouter()
	s.AddRoutes(virtualHostStyle, "/", "/{key:.+}")

	return s, nil
}

// AddRoutes adds handlers to path-style and virtual-host style routes.
func (s *Server) AddRoutes(r *mux.Router, bucketPath, objectPath string) {
	r.HandleFunc(objectPath, s.DeleteObjectTagging).Methods(http.MethodDelete).Queries("tagging", "")
	r.HandleFunc(objectPath, s.GetObjectTagging).Methods(http.MethodGet).Queries("tagging", "")
	r.HandleFunc(objectPath, s.PutObjectTagging).Methods(http.MethodPut).Queries("tagging", "")

	r.HandleFunc(objectPath, s.AbortMultipartUpload).Methods(http.MethodDelete).Queries("uploadId", "{UploadId:.+}")
	r.HandleFunc(objectPath, s.ListParts).Methods(http.MethodGet).Queries("uploadId", "{UploadId:.+}")
	r.HandleFunc(objectPath, s.CreateMultipartUpload).Methods(http.MethodPost).Queries("uploads", "")
	r.HandleFunc(objectPath, s.CompleteMultipartUpload).Methods(http.MethodPost).Queries("uploadId", "{UploadId:.+}")
	r.HandleFunc(objectPath, s.UploadPartCopy).Methods(http.MethodPut).Queries("uploadId", "{UploadId:.+}", "partNumber", "{partNumber:.+}").HeadersRegexp("x-amz-copy-source", ".+")
	r.HandleFunc(objectPath, s.UploadPart).Methods(http.MethodPut).Queries("uploadId", "{UploadId:.+}", "partNumber", "{partNumber:.+}")

	r.HandleFunc(objectPath, s.GetObject).Methods(http.MethodGet)
	r.HandleFunc(objectPath, s.CopyObject).Methods(http.MethodPut).HeadersRegexp("x-amz-copy-source", ".+")
	r.HandleFunc(objectPath, s.PutObject).Methods(http.MethodPut)
	r.HandleFunc(objectPath, s.DeleteObject).Methods(http.MethodDelete)
	r.HandleFunc(objectPath, s.HeadObject).Methods(http.MethodHead)

	r.HandleFunc(bucketPath, s.DeleteBucketTagging).Methods(http.MethodDelete).Queries("tagging", "")
	r.HandleFunc(bucketPath, s.GetBucketTagging).Methods(http.MethodGet).Queries("tagging", "")
	r.HandleFunc(bucketPath, s.PutBucketTagging).Methods(http.MethodPut).Queries("tagging", "")

	r.HandleFunc(bucketPath, s.DeleteObjects).Methods(http.MethodPost).Queries("delete", "")
	r.HandleFunc(bucketPath, s.ListMultipartUploads).Methods(http.MethodGet).Queries("uploads", "")
	r.HandleFunc(bucketPath, s.ListObjectsV2).Methods(http.MethodGet).Queries("list-type", "2")
	r.HandleFunc(bucketPath, s.ListObjects).Methods(http.MethodGet)
	r.HandleFunc(bucketPath, s.CreateBucket).Methods(http.MethodPut)
	r.HandleFunc(bucketPath, s.DeleteBucket).Methods(http.MethodDelete)
	r.HandleFunc(bucketPath, s.HeadBucket).Methods(http.MethodHead)
}

// Run starts the S3 compatible http server.
func (s *Server) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	var group errgroup.Group
	group.Go(func() error {
		<-ctx.Done()
		return Error.Wrap(s.http.Shutdown(context.Background()))
	})
	group.Go(func() error {
		defer cancel()
		err := s.http.Serve(s.listener)
		if errs2.IsCanceled(err) || errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		return Error.Wrap(err)
	})
	return group.Wait()
}

// Close closes server and underlying listener.
func (s *Server) Close() error {
	return Error.Wrap(s.http.Close())
}

// AbortMultipartUpload aborts a multipart upload.
func (s *Server) AbortMultipartUpload(w http.ResponseWriter, r *http.Request) {
	s.log.Debug("AbortMultipartUpload")
}

// CompleteMultipartUpload completes a mulitpart upload.
func (s *Server) CompleteMultipartUpload(w http.ResponseWriter, r *http.Request) {
	s.log.Debug("CompleteMultipartUpload")
}

// CopyObject copies and object.
func (s *Server) CopyObject(w http.ResponseWriter, r *http.Request) {
	s.log.Debug("CopyObject")
}

// CreateBucket creates a bucket.
func (s *Server) CreateBucket(w http.ResponseWriter, r *http.Request) {
	s.log.Debug("CreateBucket")
}

// CreateMultipartUpload creates a multipart upload.
func (s *Server) CreateMultipartUpload(w http.ResponseWriter, r *http.Request) {
	s.log.Debug("CreateMultipartUpload")
}

// DeleteBucket deletes a bucket.
func (s *Server) DeleteBucket(w http.ResponseWriter, r *http.Request) {
	s.log.Debug("DeleteBucket")
}

// DeleteBucketTagging deletes the tagging of a bucket.
func (s *Server) DeleteBucketTagging(w http.ResponseWriter, r *http.Request) {
	s.log.Debug("DeleteBucketTagging")
}

// DeleteObject deletes an object.
func (s *Server) DeleteObject(w http.ResponseWriter, r *http.Request) {
	s.log.Debug("DeleteObject")
}

// DeleteObjectTagging deletes the tagging of an object.
func (s *Server) DeleteObjectTagging(w http.ResponseWriter, r *http.Request) {
	s.log.Debug("DeleteObjectTagging")
}

// DeleteObjects deletes objects.
func (s *Server) DeleteObjects(w http.ResponseWriter, r *http.Request) {
	s.log.Debug("DeleteObjects")
}

// GetBucketTagging deletes the tagging of a bucket.
func (s *Server) GetBucketTagging(w http.ResponseWriter, r *http.Request) {
	s.log.Debug("GetBucketTagging")
}

// GetObject returns an object.
func (s *Server) GetObject(w http.ResponseWriter, r *http.Request) {
	s.log.Debug("GetObject")
}

// GetObjectTagging returns the tagging of an object.
func (s *Server) GetObjectTagging(w http.ResponseWriter, r *http.Request) {
	s.log.Debug("GetObjectTagging")
}

// HeadBucket returns http headers about a bucket.
func (s *Server) HeadBucket(w http.ResponseWriter, r *http.Request) {
	s.log.Debug("HeadBucket")
}

// HeadObject returns http headers about an object.
func (s *Server) HeadObject(w http.ResponseWriter, r *http.Request) {
	s.log.Debug("HeadObject")
}

// ListBuckets returns a list of buckets.
func (s *Server) ListBuckets(w http.ResponseWriter, r *http.Request) {
	s.log.Debug("ListBuckets")
}

// ListMultipartUploads returns a list of multipart uploads.
func (s *Server) ListMultipartUploads(w http.ResponseWriter, r *http.Request) {
	s.log.Debug("ListMultipartUploads")
}

// ListObjects returns a list of objects.
func (s *Server) ListObjects(w http.ResponseWriter, r *http.Request) {
	s.log.Debug("ListObjects")
}

// ListObjectsV2 returns a list of objects.
func (s *Server) ListObjectsV2(w http.ResponseWriter, r *http.Request) {
	s.log.Debug("ListObjectsV2")
}

// ListParts returns a list of parts of a multipart upload.
func (s *Server) ListParts(w http.ResponseWriter, r *http.Request) {
	s.log.Debug("ListParts")
}

// PutBucketTagging adds tagging to a bucket.
func (s *Server) PutBucketTagging(w http.ResponseWriter, r *http.Request) {
	s.log.Debug("PutBucketTagging")
}

// PutObject uploads an objects.
func (s *Server) PutObject(w http.ResponseWriter, r *http.Request) {
	s.log.Debug("PutObject")
}

// PutObjectTagging adds tagging to an object.
func (s *Server) PutObjectTagging(w http.ResponseWriter, r *http.Request) {
	s.log.Debug("PutObjectTagging")
}

// UploadPart uploads part of a mulitpart upload.
func (s *Server) UploadPart(w http.ResponseWriter, r *http.Request) {
	s.log.Debug("UploadPart")
}

// UploadPartCopy copies part of a multipart upload to another object.
func (s *Server) UploadPartCopy(w http.ResponseWriter, r *http.Request) {
	s.log.Debug("UploadPartCopy")
}
