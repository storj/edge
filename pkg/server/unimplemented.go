// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"net/http"
)

// AbortMultipartUpload aborts a multipart upload.
func (s *Server) AbortMultipartUpload(w http.ResponseWriter, r *http.Request) {
	s.log.Debug("AbortMultipartUpload")
}

// CompleteMultipartUpload completes a multipart upload.
func (s *Server) CompleteMultipartUpload(w http.ResponseWriter, r *http.Request) {
	s.log.Debug("CompleteMultipartUpload")
}

// CopyObject copies and object.
func (s *Server) CopyObject(w http.ResponseWriter, r *http.Request) {
	s.log.Debug("CopyObject")
}

// CreateMultipartUpload creates a multipart upload.
func (s *Server) CreateMultipartUpload(w http.ResponseWriter, r *http.Request) {
	s.log.Debug("CreateMultipartUpload")
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

// HeadObject returns http headers about an object.
func (s *Server) HeadObject(w http.ResponseWriter, r *http.Request) {
	s.log.Debug("HeadObject")
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

// UploadPart uploads part of a multipart upload.
func (s *Server) UploadPart(w http.ResponseWriter, r *http.Request) {
	s.log.Debug("UploadPart")
}

// UploadPartCopy copies part of a multipart upload to another object.
func (s *Server) UploadPartCopy(w http.ResponseWriter, r *http.Request) {
	s.log.Debug("UploadPartCopy")
}
