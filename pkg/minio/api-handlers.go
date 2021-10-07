// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package minio

import (
	"net/http"

	"storj.io/minio/cmd"
)

type objectAPIHandlers struct {
	ObjectAPI func() cmd.ObjectLayer
	CacheAPI  func() cmd.CacheObjectLayer
}

func (h objectAPIHandlers) HeadObjectHandler(w http.ResponseWriter, r *http.Request) {
	HeadObjectHandler(h, w, r)
}

func (h objectAPIHandlers) CopyObjectPartHandler(w http.ResponseWriter, r *http.Request) {
	CopyObjectPartHandler(h, w, r)
}

func (h objectAPIHandlers) PutObjectPartHandler(w http.ResponseWriter, r *http.Request) {
	PutObjectPartHandler(h, w, r)
}

func (h objectAPIHandlers) ListObjectPartsHandler(w http.ResponseWriter, r *http.Request) {
	ListObjectPartsHandler(h, w, r)
}

func (h objectAPIHandlers) CompleteMultipartUploadHandler(w http.ResponseWriter, r *http.Request) {
	CompleteMultipartUploadHandler(h, w, r)
}

func (h objectAPIHandlers) NewMultipartUploadHandler(w http.ResponseWriter, r *http.Request) {
	NewMultipartUploadHandler(h, w, r)
}

func (h objectAPIHandlers) AbortMultipartUploadHandler(w http.ResponseWriter, r *http.Request) {
	AbortMultipartUploadHandler(h, w, r)
}

func (h objectAPIHandlers) GetObjectACLHandler(w http.ResponseWriter, r *http.Request) {
	GetObjectACLHandler(h, w, r)
}

func (h objectAPIHandlers) PutObjectACLHandler(w http.ResponseWriter, r *http.Request) {
	PutObjectACLHandler(h, w, r)
}

func (h objectAPIHandlers) GetObjectTaggingHandler(w http.ResponseWriter, r *http.Request) {
	GetObjectTaggingHandler(h, w, r)
}

func (h objectAPIHandlers) PutObjectTaggingHandler(w http.ResponseWriter, r *http.Request) {
	PutObjectTaggingHandler(h, w, r)
}

func (h objectAPIHandlers) DeleteObjectTaggingHandler(w http.ResponseWriter, r *http.Request) {
	DeleteObjectTaggingHandler(h, w, r)
}

func (h objectAPIHandlers) SelectObjectContentHandler(w http.ResponseWriter, r *http.Request) {
	SelectObjectContentHandler(h, w, r)
}

func (h objectAPIHandlers) GetObjectRetentionHandler(w http.ResponseWriter, r *http.Request) {
	GetObjectRetentionHandler(h, w, r)
}

func (h objectAPIHandlers) GetObjectLegalHoldHandler(w http.ResponseWriter, r *http.Request) {
	GetObjectLegalHoldHandler(h, w, r)
}

func (h objectAPIHandlers) GetObjectHandler(w http.ResponseWriter, r *http.Request) {
	GetObjectHandler(h, w, r)
}

func (h objectAPIHandlers) CopyObjectHandler(w http.ResponseWriter, r *http.Request) {
	CopyObjectHandler(h, w, r)
}

func (h objectAPIHandlers) PutObjectRetentionHandler(w http.ResponseWriter, r *http.Request) {
	PutObjectRetentionHandler(h, w, r)
}

func (h objectAPIHandlers) PutObjectLegalHoldHandler(w http.ResponseWriter, r *http.Request) {
	PutObjectLegalHoldHandler(h, w, r)
}

func (h objectAPIHandlers) PutObjectHandler(w http.ResponseWriter, r *http.Request) {
	PutObjectHandler(h, w, r)
}

func (h objectAPIHandlers) DeleteObjectHandler(w http.ResponseWriter, r *http.Request) {
	DeleteObjectHandler(h, w, r)
}

func (h objectAPIHandlers) GetBucketLocationHandler(w http.ResponseWriter, r *http.Request) {
	GetBucketLocationHandler(h, w, r)
}

func (h objectAPIHandlers) GetBucketPolicyHandler(w http.ResponseWriter, r *http.Request) {
	GetBucketPolicyHandler(h, w, r)
}

func (h objectAPIHandlers) GetBucketLifecycleHandler(w http.ResponseWriter, r *http.Request) {
	GetBucketLifecycleHandler(h, w, r)
}

func (h objectAPIHandlers) GetBucketEncryptionHandler(w http.ResponseWriter, r *http.Request) {
	GetBucketEncryptionHandler(h, w, r)
}

func (h objectAPIHandlers) GetBucketObjectLockConfigHandler(w http.ResponseWriter, r *http.Request) {
	GetBucketObjectLockConfigHandler(h, w, r)
}

func (h objectAPIHandlers) GetBucketReplicationConfigHandler(w http.ResponseWriter, r *http.Request) {
	GetBucketReplicationConfigHandler(h, w, r)
}

func (h objectAPIHandlers) GetBucketVersioningHandler(w http.ResponseWriter, r *http.Request) {
	GetBucketVersioningHandler(h, w, r)
}

func (h objectAPIHandlers) GetBucketNotificationHandler(w http.ResponseWriter, r *http.Request) {
	GetBucketNotificationHandler(h, w, r)
}

func (h objectAPIHandlers) ListenNotificationHandler(w http.ResponseWriter, r *http.Request) {
	ListenNotificationHandler(h, w, r)
}

func (h objectAPIHandlers) GetBucketACLHandler(w http.ResponseWriter, r *http.Request) {
	GetBucketACLHandler(h, w, r)
}

func (h objectAPIHandlers) PutBucketACLHandler(w http.ResponseWriter, r *http.Request) {
	PutBucketACLHandler(h, w, r)
}

func (h objectAPIHandlers) GetBucketCorsHandler(w http.ResponseWriter, r *http.Request) {
	GetBucketCorsHandler(h, w, r)
}

func (h objectAPIHandlers) GetBucketWebsiteHandler(w http.ResponseWriter, r *http.Request) {
	GetBucketWebsiteHandler(h, w, r)
}

func (h objectAPIHandlers) GetBucketAccelerateHandler(w http.ResponseWriter, r *http.Request) {
	GetBucketAccelerateHandler(h, w, r)
}

func (h objectAPIHandlers) GetBucketRequestPaymentHandler(w http.ResponseWriter, r *http.Request) {
	GetBucketRequestPaymentHandler(h, w, r)
}

func (h objectAPIHandlers) GetBucketLoggingHandler(w http.ResponseWriter, r *http.Request) {
	GetBucketLoggingHandler(h, w, r)
}

func (h objectAPIHandlers) GetBucketTaggingHandler(w http.ResponseWriter, r *http.Request) {
	GetBucketTaggingHandler(h, w, r)
}

func (h objectAPIHandlers) DeleteBucketWebsiteHandler(w http.ResponseWriter, r *http.Request) {
	DeleteBucketWebsiteHandler(h, w, r)
}

func (h objectAPIHandlers) DeleteBucketTaggingHandler(w http.ResponseWriter, r *http.Request) {
	DeleteBucketTaggingHandler(h, w, r)
}

func (h objectAPIHandlers) ListMultipartUploadsHandler(w http.ResponseWriter, r *http.Request) {
	ListMultipartUploadsHandler(h, w, r)
}

func (h objectAPIHandlers) ListObjectsV2MHandler(w http.ResponseWriter, r *http.Request) {
	ListObjectsV2MHandler(h, w, r)
}

func (h objectAPIHandlers) ListObjectsV2Handler(w http.ResponseWriter, r *http.Request) {
	ListObjectsV2Handler(h, w, r)
}

func (h objectAPIHandlers) ListObjectVersionsHandler(w http.ResponseWriter, r *http.Request) {
	ListObjectVersionsHandler(h, w, r)
}

func (h objectAPIHandlers) ListObjectsV1Handler(w http.ResponseWriter, r *http.Request) {
	ListObjectsV1Handler(h, w, r)
}

func (h objectAPIHandlers) PutBucketLifecycleHandler(w http.ResponseWriter, r *http.Request) {
	PutBucketLifecycleHandler(h, w, r)
}

func (h objectAPIHandlers) PutBucketReplicationConfigHandler(w http.ResponseWriter, r *http.Request) {
	PutBucketReplicationConfigHandler(h, w, r)
}

func (h objectAPIHandlers) PutBucketEncryptionHandler(w http.ResponseWriter, r *http.Request) {
	PutBucketEncryptionHandler(h, w, r)
}

func (h objectAPIHandlers) PutBucketPolicyHandler(w http.ResponseWriter, r *http.Request) {
	PutBucketPolicyHandler(h, w, r)
}

func (h objectAPIHandlers) PutBucketObjectLockConfigHandler(w http.ResponseWriter, r *http.Request) {
	PutBucketObjectLockConfigHandler(h, w, r)
}

func (h objectAPIHandlers) PutBucketTaggingHandler(w http.ResponseWriter, r *http.Request) {
	PutBucketTaggingHandler(h, w, r)
}

func (h objectAPIHandlers) PutBucketVersioningHandler(w http.ResponseWriter, r *http.Request) {
	PutBucketVersioningHandler(h, w, r)
}

func (h objectAPIHandlers) PutBucketNotificationHandler(w http.ResponseWriter, r *http.Request) {
	PutBucketNotificationHandler(h, w, r)
}

func (h objectAPIHandlers) PutBucketHandler(w http.ResponseWriter, r *http.Request) {
	PutBucketHandler(h, w, r)
}

func (h objectAPIHandlers) HeadBucketHandler(w http.ResponseWriter, r *http.Request) {
	HeadBucketHandler(h, w, r)
}

func (h objectAPIHandlers) PostPolicyBucketHandler(w http.ResponseWriter, r *http.Request) {
	PostPolicyBucketHandler(h, w, r)
}

func (h objectAPIHandlers) DeleteMultipleObjectsHandler(w http.ResponseWriter, r *http.Request) {
	DeleteMultipleObjectsHandler(h, w, r)
}

func (h objectAPIHandlers) DeleteBucketPolicyHandler(w http.ResponseWriter, r *http.Request) {
	DeleteBucketPolicyHandler(h, w, r)
}

func (h objectAPIHandlers) DeleteBucketReplicationConfigHandler(w http.ResponseWriter, r *http.Request) {
	DeleteBucketReplicationConfigHandler(h, w, r)
}

func (h objectAPIHandlers) DeleteBucketLifecycleHandler(w http.ResponseWriter, r *http.Request) {
	DeleteBucketLifecycleHandler(h, w, r)
}

func (h objectAPIHandlers) DeleteBucketEncryptionHandler(w http.ResponseWriter, r *http.Request) {
	DeleteBucketEncryptionHandler(h, w, r)
}

func (h objectAPIHandlers) DeleteBucketHandler(w http.ResponseWriter, r *http.Request) {
	DeleteBucketHandler(h, w, r)
}

func (h objectAPIHandlers) PostRestoreObjectHandler(w http.ResponseWriter, r *http.Request) {
	PostRestoreObjectHandler(h, w, r)
}

func (h objectAPIHandlers) ListBucketsHandler(w http.ResponseWriter, r *http.Request) {
	ListBucketsHandler(h, w, r)
}
