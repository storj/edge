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
	HeadObjectHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) CopyObjectPartHandler(w http.ResponseWriter, r *http.Request) {
	CopyObjectPartHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PutObjectPartHandler(w http.ResponseWriter, r *http.Request) {
	PutObjectPartHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) ListObjectPartsHandler(w http.ResponseWriter, r *http.Request) {
	ListObjectPartsHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) CompleteMultipartUploadHandler(w http.ResponseWriter, r *http.Request) {
	CompleteMultipartUploadHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) NewMultipartUploadHandler(w http.ResponseWriter, r *http.Request) {
	NewMultipartUploadHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) AbortMultipartUploadHandler(w http.ResponseWriter, r *http.Request) {
	AbortMultipartUploadHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetObjectACLHandler(w http.ResponseWriter, r *http.Request) {
	GetObjectACLHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PutObjectACLHandler(w http.ResponseWriter, r *http.Request) {
	PutObjectACLHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetObjectTaggingHandler(w http.ResponseWriter, r *http.Request) {
	GetObjectTaggingHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PutObjectTaggingHandler(w http.ResponseWriter, r *http.Request) {
	PutObjectTaggingHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) DeleteObjectTaggingHandler(w http.ResponseWriter, r *http.Request) {
	DeleteObjectTaggingHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) SelectObjectContentHandler(w http.ResponseWriter, r *http.Request) {
	SelectObjectContentHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetObjectRetentionHandler(w http.ResponseWriter, r *http.Request) {
	GetObjectRetentionHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetObjectLegalHoldHandler(w http.ResponseWriter, r *http.Request) {
	GetObjectLegalHoldHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetObjectHandler(w http.ResponseWriter, r *http.Request) {
	GetObjectHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) CopyObjectHandler(w http.ResponseWriter, r *http.Request) {
	CopyObjectHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PutObjectRetentionHandler(w http.ResponseWriter, r *http.Request) {
	PutObjectRetentionHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PutObjectLegalHoldHandler(w http.ResponseWriter, r *http.Request) {
	PutObjectLegalHoldHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PutObjectHandler(w http.ResponseWriter, r *http.Request) {
	PutObjectHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) DeleteObjectHandler(w http.ResponseWriter, r *http.Request) {
	DeleteObjectHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetBucketLocationHandler(w http.ResponseWriter, r *http.Request) {
	GetBucketLocationHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetBucketPolicyHandler(w http.ResponseWriter, r *http.Request) {
	GetBucketPolicyHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetBucketLifecycleHandler(w http.ResponseWriter, r *http.Request) {
	GetBucketLifecycleHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetBucketEncryptionHandler(w http.ResponseWriter, r *http.Request) {
	GetBucketEncryptionHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetBucketObjectLockConfigHandler(w http.ResponseWriter, r *http.Request) {
	GetBucketObjectLockConfigHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetBucketReplicationConfigHandler(w http.ResponseWriter, r *http.Request) {
	GetBucketReplicationConfigHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetBucketVersioningHandler(w http.ResponseWriter, r *http.Request) {
	GetBucketVersioningHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetBucketNotificationHandler(w http.ResponseWriter, r *http.Request) {
	GetBucketNotificationHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) ListenNotificationHandler(w http.ResponseWriter, r *http.Request) {
	ListenNotificationHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetBucketACLHandler(w http.ResponseWriter, r *http.Request) {
	GetBucketACLHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PutBucketACLHandler(w http.ResponseWriter, r *http.Request) {
	PutBucketACLHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetBucketCorsHandler(w http.ResponseWriter, r *http.Request) {
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
	WriteResponse(w, http.StatusOK, []byte(sb.String()), "application/xml")
}

func (h objectAPIHandlersWrapper) PutBucketCorsHandler(w http.ResponseWriter, r *http.Request) {
	WriteErrorResponse(r.Context(), w, GetAPIError(cmd.ErrNotImplemented), r.URL, false)
}

func (h objectAPIHandlersWrapper) DeleteBucketCorsHandler(w http.ResponseWriter, r *http.Request) {
	WriteErrorResponse(r.Context(), w, GetAPIError(cmd.ErrNotImplemented), r.URL, false)
}

func (h objectAPIHandlersWrapper) GetBucketWebsiteHandler(w http.ResponseWriter, r *http.Request) {
	GetBucketWebsiteHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetBucketAccelerateHandler(w http.ResponseWriter, r *http.Request) {
	GetBucketAccelerateHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetBucketRequestPaymentHandler(w http.ResponseWriter, r *http.Request) {
	GetBucketRequestPaymentHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetBucketLoggingHandler(w http.ResponseWriter, r *http.Request) {
	GetBucketLoggingHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) GetBucketTaggingHandler(w http.ResponseWriter, r *http.Request) {
	GetBucketTaggingHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) DeleteBucketWebsiteHandler(w http.ResponseWriter, r *http.Request) {
	DeleteBucketWebsiteHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) DeleteBucketTaggingHandler(w http.ResponseWriter, r *http.Request) {
	DeleteBucketTaggingHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) ListMultipartUploadsHandler(w http.ResponseWriter, r *http.Request) {
	ListMultipartUploadsHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) ListObjectsV2MHandler(w http.ResponseWriter, r *http.Request) {
	ListObjectsV2MHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) ListObjectsV2Handler(w http.ResponseWriter, r *http.Request) {
	ListObjectsV2Handler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) ListObjectVersionsHandler(w http.ResponseWriter, r *http.Request) {
	ListObjectVersionsHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) ListObjectsV1Handler(w http.ResponseWriter, r *http.Request) {
	ListObjectsV1Handler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PutBucketLifecycleHandler(w http.ResponseWriter, r *http.Request) {
	PutBucketLifecycleHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PutBucketReplicationConfigHandler(w http.ResponseWriter, r *http.Request) {
	PutBucketReplicationConfigHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PutBucketEncryptionHandler(w http.ResponseWriter, r *http.Request) {
	PutBucketEncryptionHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PutBucketPolicyHandler(w http.ResponseWriter, r *http.Request) {
	PutBucketPolicyHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PutBucketObjectLockConfigHandler(w http.ResponseWriter, r *http.Request) {
	PutBucketObjectLockConfigHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PutBucketTaggingHandler(w http.ResponseWriter, r *http.Request) {
	PutBucketTaggingHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PutBucketVersioningHandler(w http.ResponseWriter, r *http.Request) {
	PutBucketVersioningHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PutBucketNotificationHandler(w http.ResponseWriter, r *http.Request) {
	PutBucketNotificationHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PutBucketHandler(w http.ResponseWriter, r *http.Request) {
	PutBucketHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) HeadBucketHandler(w http.ResponseWriter, r *http.Request) {
	HeadBucketHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PostPolicyBucketHandler(w http.ResponseWriter, r *http.Request) {
	PostPolicyBucketHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) DeleteMultipleObjectsHandler(w http.ResponseWriter, r *http.Request) {
	DeleteMultipleObjectsHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) DeleteBucketPolicyHandler(w http.ResponseWriter, r *http.Request) {
	DeleteBucketPolicyHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) DeleteBucketReplicationConfigHandler(w http.ResponseWriter, r *http.Request) {
	DeleteBucketReplicationConfigHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) DeleteBucketLifecycleHandler(w http.ResponseWriter, r *http.Request) {
	DeleteBucketLifecycleHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) DeleteBucketEncryptionHandler(w http.ResponseWriter, r *http.Request) {
	DeleteBucketEncryptionHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) DeleteBucketHandler(w http.ResponseWriter, r *http.Request) {
	DeleteBucketHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) PostRestoreObjectHandler(w http.ResponseWriter, r *http.Request) {
	PostRestoreObjectHandler(h.core, w, r)
}

func (h objectAPIHandlersWrapper) ListBucketsHandler(w http.ResponseWriter, r *http.Request) {
	ListBucketsHandler(h.core, w, r)
}
