// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package minio

import (
	"fmt"
	"net/http"
	"strings"

	"storj.io/minio/cmd"
)

// objectAPIHandlers is linked to Minio's cmd.objectAPIHandlers and should not be changed.
type objectAPIHandlers struct {
	ObjectAPI func() cmd.ObjectLayer
	CacheAPI  func() cmd.CacheObjectLayer
}

// objectAPIHandlersWrapper should be used to extend objectAPIHandlers.
type objectAPIHandlersWrapper struct {
	core               objectAPIHandlers
	corsAllowedOrigins []string
}

func (h objectAPIHandlersWrapper) HeadObjectHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	HeadObjectHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) CopyObjectPartHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	CopyObjectPartHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PutObjectPartHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	PutObjectPartHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) ListObjectPartsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	ListObjectPartsHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) CompleteMultipartUploadHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	CompleteMultipartUploadHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) NewMultipartUploadHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	NewMultipartUploadHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) AbortMultipartUploadHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	AbortMultipartUploadHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetObjectACLHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	GetObjectACLHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PutObjectACLHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	PutObjectACLHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetObjectTaggingHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	GetObjectTaggingHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PutObjectTaggingHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	PutObjectTaggingHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) DeleteObjectTaggingHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	DeleteObjectTaggingHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) SelectObjectContentHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	SelectObjectContentHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetObjectRetentionHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	GetObjectRetentionHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetObjectLegalHoldHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	GetObjectLegalHoldHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetObjectHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	GetObjectHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) CopyObjectHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	CopyObjectHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PutObjectRetentionHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	PutObjectRetentionHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PutObjectLegalHoldHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	PutObjectLegalHoldHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PutObjectHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	PutObjectHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) DeleteObjectHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	DeleteObjectHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetBucketLocationHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	GetBucketLocationHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetBucketPolicyHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	GetBucketPolicyHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetBucketLifecycleHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	GetBucketLifecycleHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetBucketEncryptionHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	GetBucketEncryptionHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetBucketObjectLockConfigHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	GetBucketObjectLockConfigHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetBucketReplicationConfigHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	GetBucketReplicationConfigHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetBucketVersioningHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	GetBucketVersioningHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetBucketNotificationHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	GetBucketNotificationHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) ListenNotificationHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	ListenNotificationHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetBucketACLHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	GetBucketACLHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PutBucketACLHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	PutBucketACLHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetBucketCorsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	var sb strings.Builder
	sb.WriteString("<CORSConfiguration><CORSRule>")
	for _, o := range h.corsAllowedOrigins {
		fmt.Fprintf(&sb, "<AllowedOrigin>%s</AllowedOrigin>", o)
	}
	// CorsHandler's AllowedHeader list is duplicated here
	allowedMethods := []string{http.MethodGet, http.MethodPut, http.MethodHead, http.MethodPost,
		http.MethodDelete, http.MethodOptions, http.MethodPatch}
	for _, o := range allowedMethods {
		fmt.Fprintf(&sb, "<AllowedMethod>%s</AllowedMethod>", o)
	}
	// CorsHandler's AllowedHeader list is not implemented here, because it includes "*"
	sb.WriteString("<AllowedHeader>*</AllowedHeader><ExposeHeader>*</ExposeHeader></CORSRule></CORSConfiguration>")
	writeSuccessResponseXML(w, []byte(sb.String()))
}

func (h objectAPIHandlersWrapper) PutBucketCorsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	writeErrorResponse(r.Context(), w, GetAPIError(cmd.ErrNotImplemented), r.URL, false)
}

func (h objectAPIHandlersWrapper) DeleteBucketCorsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	writeErrorResponse(r.Context(), w, GetAPIError(cmd.ErrNotImplemented), r.URL, false)
}

func (h objectAPIHandlersWrapper) GetBucketWebsiteHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	GetBucketWebsiteHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetBucketAccelerateHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	GetBucketAccelerateHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetBucketRequestPaymentHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	GetBucketRequestPaymentHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetBucketLoggingHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	GetBucketLoggingHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetBucketTaggingHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	GetBucketTaggingHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) DeleteBucketWebsiteHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	DeleteBucketWebsiteHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) DeleteBucketTaggingHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	DeleteBucketTaggingHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) ListMultipartUploadsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	ListMultipartUploadsHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) ListObjectsV2MHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	ListObjectsV2MHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) ListObjectsV2Handler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	ListObjectsV2Handler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) ListObjectVersionsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	ListObjectVersionsHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) ListObjectsV1Handler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	ListObjectsV1Handler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PutBucketLifecycleHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	PutBucketLifecycleHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PutBucketReplicationConfigHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	PutBucketReplicationConfigHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PutBucketEncryptionHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	PutBucketEncryptionHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PutBucketPolicyHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	PutBucketPolicyHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PutBucketObjectLockConfigHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	PutBucketObjectLockConfigHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PutBucketTaggingHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	PutBucketTaggingHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PutBucketVersioningHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	PutBucketVersioningHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PutBucketNotificationHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	PutBucketNotificationHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PutBucketHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	PutBucketHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) HeadBucketHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	HeadBucketHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PostPolicyBucketHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	PostPolicyBucketHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) DeleteMultipleObjectsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	DeleteMultipleObjectsHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) DeleteBucketPolicyHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	DeleteBucketPolicyHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) DeleteBucketReplicationConfigHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	DeleteBucketReplicationConfigHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) DeleteBucketLifecycleHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	DeleteBucketLifecycleHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) DeleteBucketEncryptionHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	DeleteBucketEncryptionHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) DeleteBucketHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	DeleteBucketHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PostRestoreObjectHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	PostRestoreObjectHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) ListBucketsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	ListBucketsHandler(h.core, w, r)
}
