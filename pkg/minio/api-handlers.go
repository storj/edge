// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package minio

import (
	"fmt"
	"net/http"
	"strings"

	"storj.io/minio/cmd"
)

// objectAPIHandlersWrapper should be used to extend cmd.ObjectAPIHandlers.
type objectAPIHandlersWrapper struct {
	core               cmd.ObjectAPIHandlers
	corsAllowedOrigins []string
}

func (h objectAPIHandlersWrapper) HeadObjectHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.HeadObjectHandler(w, r)
}

func (h objectAPIHandlersWrapper) CopyObjectPartHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.CopyObjectPartHandler(w, r)
}

func (h objectAPIHandlersWrapper) PutObjectPartHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.PutObjectPartHandler(w, r)
}

func (h objectAPIHandlersWrapper) ListObjectPartsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.ListObjectPartsHandler(w, r)
}

func (h objectAPIHandlersWrapper) CompleteMultipartUploadHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.CompleteMultipartUploadHandler(w, r)
}

func (h objectAPIHandlersWrapper) NewMultipartUploadHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.NewMultipartUploadHandler(w, r)
}

func (h objectAPIHandlersWrapper) AbortMultipartUploadHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.AbortMultipartUploadHandler(w, r)
}

func (h objectAPIHandlersWrapper) GetObjectACLHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.GetObjectACLHandler(w, r)
}

func (h objectAPIHandlersWrapper) PutObjectACLHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.PutObjectACLHandler(w, r)
}

func (h objectAPIHandlersWrapper) GetObjectTaggingHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.GetObjectTaggingHandler(w, r)
}

func (h objectAPIHandlersWrapper) PutObjectTaggingHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.PutObjectTaggingHandler(w, r)
}

func (h objectAPIHandlersWrapper) DeleteObjectTaggingHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.DeleteObjectTaggingHandler(w, r)
}

func (h objectAPIHandlersWrapper) SelectObjectContentHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.SelectObjectContentHandler(w, r)
}

func (h objectAPIHandlersWrapper) GetObjectRetentionHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.GetObjectRetentionHandler(w, r)
}

func (h objectAPIHandlersWrapper) GetObjectLegalHoldHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.GetObjectLegalHoldHandler(w, r)
}

func (h objectAPIHandlersWrapper) GetObjectHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.GetObjectHandler(w, r)
}

func (h objectAPIHandlersWrapper) CopyObjectHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.CopyObjectHandler(w, r)
}

func (h objectAPIHandlersWrapper) PutObjectRetentionHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.PutObjectRetentionHandler(w, r)
}

func (h objectAPIHandlersWrapper) PutObjectLegalHoldHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.PutObjectLegalHoldHandler(w, r)
}

func (h objectAPIHandlersWrapper) PutObjectHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.PutObjectHandler(w, r)
}

func (h objectAPIHandlersWrapper) DeleteObjectHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.DeleteObjectHandler(w, r)
}

func (h objectAPIHandlersWrapper) GetBucketLocationHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.GetBucketLocationHandler(w, r)
}

func (h objectAPIHandlersWrapper) GetBucketPolicyHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.GetBucketPolicyHandler(w, r)
}

func (h objectAPIHandlersWrapper) GetBucketLifecycleHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.GetBucketLifecycleHandler(w, r)
}

func (h objectAPIHandlersWrapper) GetBucketEncryptionHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.GetBucketEncryptionHandler(w, r)
}

func (h objectAPIHandlersWrapper) GetBucketObjectLockConfigHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.GetBucketObjectLockConfigHandler(w, r)
}

func (h objectAPIHandlersWrapper) GetBucketReplicationConfigHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.GetBucketReplicationConfigHandler(w, r)
}

func (h objectAPIHandlersWrapper) GetBucketVersioningHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.GetBucketVersioningHandler(w, r)
}

func (h objectAPIHandlersWrapper) GetBucketNotificationHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.GetBucketNotificationHandler(w, r)
}

func (h objectAPIHandlersWrapper) ListenNotificationHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.ListenNotificationHandler(w, r)
}

func (h objectAPIHandlersWrapper) GetBucketACLHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.GetBucketACLHandler(w, r)
}

func (h objectAPIHandlersWrapper) PutBucketACLHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.PutBucketACLHandler(w, r)
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
	cmd.WriteSuccessResponseXML(w, []byte(sb.String()))
}

func (h objectAPIHandlersWrapper) PutBucketCorsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	cmd.WriteErrorResponse(r.Context(), w, cmd.GetAPIError(cmd.ErrNotImplemented), r.URL, false)
}

func (h objectAPIHandlersWrapper) DeleteBucketCorsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	cmd.WriteErrorResponse(r.Context(), w, cmd.GetAPIError(cmd.ErrNotImplemented), r.URL, false)
}

func (h objectAPIHandlersWrapper) GetBucketWebsiteHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.GetBucketWebsiteHandler(w, r)
}

func (h objectAPIHandlersWrapper) GetBucketAccelerateHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.GetBucketAccelerateHandler(w, r)
}

func (h objectAPIHandlersWrapper) GetBucketRequestPaymentHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.GetBucketRequestPaymentHandler(w, r)
}

func (h objectAPIHandlersWrapper) GetBucketLoggingHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.GetBucketLoggingHandler(w, r)
}

func (h objectAPIHandlersWrapper) GetBucketTaggingHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.GetBucketTaggingHandler(w, r)
}

func (h objectAPIHandlersWrapper) DeleteBucketWebsiteHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.DeleteBucketWebsiteHandler(w, r)
}

func (h objectAPIHandlersWrapper) DeleteBucketTaggingHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.DeleteBucketTaggingHandler(w, r)
}

func (h objectAPIHandlersWrapper) ListMultipartUploadsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.ListMultipartUploadsHandler(w, r)
}

func (h objectAPIHandlersWrapper) ListObjectsV2MHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.ListObjectsV2MHandler(w, r)
}

func (h objectAPIHandlersWrapper) ListObjectsV2Handler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.ListObjectsV2Handler(w, r)
}

func (h objectAPIHandlersWrapper) ListObjectVersionsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.ListObjectVersionsHandler(w, r)
}

func (h objectAPIHandlersWrapper) ListObjectsV1Handler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.ListObjectsV1Handler(w, r)
}

func (h objectAPIHandlersWrapper) PutBucketLifecycleHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.PutBucketLifecycleHandler(w, r)
}

func (h objectAPIHandlersWrapper) PutBucketReplicationConfigHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.PutBucketReplicationConfigHandler(w, r)
}

func (h objectAPIHandlersWrapper) PutBucketEncryptionHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.PutBucketEncryptionHandler(w, r)
}

func (h objectAPIHandlersWrapper) PutBucketPolicyHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.PutBucketPolicyHandler(w, r)
}

func (h objectAPIHandlersWrapper) PutBucketObjectLockConfigHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.PutBucketObjectLockConfigHandler(w, r)
}

func (h objectAPIHandlersWrapper) PutBucketTaggingHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.PutBucketTaggingHandler(w, r)
}

func (h objectAPIHandlersWrapper) PutBucketVersioningHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.PutBucketVersioningHandler(w, r)
}

func (h objectAPIHandlersWrapper) PutBucketNotificationHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.PutBucketNotificationHandler(w, r)
}

func (h objectAPIHandlersWrapper) PutBucketHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.PutBucketHandler(w, r)
}

func (h objectAPIHandlersWrapper) HeadBucketHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.HeadBucketHandler(w, r)
}

func (h objectAPIHandlersWrapper) PostPolicyBucketHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.PostPolicyBucketHandler(w, r)
}

func (h objectAPIHandlersWrapper) DeleteMultipleObjectsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.DeleteMultipleObjectsHandler(w, r)
}

func (h objectAPIHandlersWrapper) DeleteBucketPolicyHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.DeleteBucketPolicyHandler(w, r)
}

func (h objectAPIHandlersWrapper) DeleteBucketReplicationConfigHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.DeleteBucketReplicationConfigHandler(w, r)
}

func (h objectAPIHandlersWrapper) DeleteBucketLifecycleHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.DeleteBucketLifecycleHandler(w, r)
}

func (h objectAPIHandlersWrapper) DeleteBucketEncryptionHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.DeleteBucketEncryptionHandler(w, r)
}

func (h objectAPIHandlersWrapper) DeleteBucketHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.DeleteBucketHandler(w, r)
}

func (h objectAPIHandlersWrapper) PostRestoreObjectHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.PostRestoreObjectHandler(w, r)
}

func (h objectAPIHandlersWrapper) ListBucketsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	h.core.ListBucketsHandler(w, r)
}
