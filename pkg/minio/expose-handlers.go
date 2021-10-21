// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package minio

import (
	"net/http"
	_ "unsafe" // for go:linkname
)

// HeadObjectHandler exposes minio's cmd.objectAPIHandlers.HeadObjectHandler
//
//nolint: golint
//go:linkname HeadObjectHandler storj.io/minio/cmd.objectAPIHandlers.HeadObjectHandler
func HeadObjectHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// CopyObjectPartHandler exposes minio's cmd.objectAPIHandlers.CopyObjectPartHandler
//
//nolint: golint
//go:linkname CopyObjectPartHandler storj.io/minio/cmd.objectAPIHandlers.CopyObjectPartHandler
func CopyObjectPartHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// PutObjectPartHandler exposes minio's cmd.objectAPIHandlers.PutObjectPartHandler
//
//nolint: golint
//go:linkname PutObjectPartHandler storj.io/minio/cmd.objectAPIHandlers.PutObjectPartHandler
func PutObjectPartHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// ListObjectPartsHandler exposes minio's cmd.objectAPIHandlers.ListObjectPartsHandler
//
//nolint: golint
//go:linkname ListObjectPartsHandler storj.io/minio/cmd.objectAPIHandlers.ListObjectPartsHandler
func ListObjectPartsHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// CompleteMultipartUploadHandler exposes minio's cmd.objectAPIHandlers.CompleteMultipartUploadHandler
//
//nolint: golint
//go:linkname CompleteMultipartUploadHandler storj.io/minio/cmd.objectAPIHandlers.CompleteMultipartUploadHandler
func CompleteMultipartUploadHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// NewMultipartUploadHandler exposes minio's cmd.objectAPIHandlers.NewMultipartUploadHandler
//
//nolint: golint
//go:linkname NewMultipartUploadHandler storj.io/minio/cmd.objectAPIHandlers.NewMultipartUploadHandler
func NewMultipartUploadHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// AbortMultipartUploadHandler exposes minio's cmd.objectAPIHandlers.AbortMultipartUploadHandler
//
//nolint: golint
//go:linkname AbortMultipartUploadHandler storj.io/minio/cmd.objectAPIHandlers.AbortMultipartUploadHandler
func AbortMultipartUploadHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// GetObjectACLHandler exposes minio's cmd.objectAPIHandlers.GetObjectACLHandler
//
//nolint: golint
//go:linkname GetObjectACLHandler storj.io/minio/cmd.objectAPIHandlers.GetObjectACLHandler
func GetObjectACLHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// PutObjectACLHandler exposes minio's cmd.objectAPIHandlers.PutObjectACLHandler
//
//nolint: golint
//go:linkname PutObjectACLHandler storj.io/minio/cmd.objectAPIHandlers.PutObjectACLHandler
func PutObjectACLHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// GetObjectTaggingHandler exposes minio's cmd.objectAPIHandlers.GetObjectTaggingHandler
//
//nolint: golint
//go:linkname GetObjectTaggingHandler storj.io/minio/cmd.objectAPIHandlers.GetObjectTaggingHandler
func GetObjectTaggingHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// PutObjectTaggingHandler exposes minio's cmd.objectAPIHandlers.PutObjectTaggingHandler
//
//nolint: golint
//go:linkname PutObjectTaggingHandler storj.io/minio/cmd.objectAPIHandlers.PutObjectTaggingHandler
func PutObjectTaggingHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// DeleteObjectTaggingHandler exposes minio's cmd.objectAPIHandlers.DeleteObjectTaggingHandler
//
//nolint: golint
//go:linkname DeleteObjectTaggingHandler storj.io/minio/cmd.objectAPIHandlers.DeleteObjectTaggingHandler
func DeleteObjectTaggingHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// SelectObjectContentHandler exposes minio's cmd.objectAPIHandlers.SelectObjectContentHandler
//
//nolint: golint
//go:linkname SelectObjectContentHandler storj.io/minio/cmd.objectAPIHandlers.SelectObjectContentHandler
func SelectObjectContentHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// GetObjectRetentionHandler exposes minio's cmd.objectAPIHandlers.GetObjectRetentionHandler
//
//nolint: golint
//go:linkname GetObjectRetentionHandler storj.io/minio/cmd.objectAPIHandlers.GetObjectRetentionHandler
func GetObjectRetentionHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// GetObjectLegalHoldHandler exposes minio's cmd.objectAPIHandlers.GetObjectLegalHoldHandler
//
//nolint: golint
//go:linkname GetObjectLegalHoldHandler storj.io/minio/cmd.objectAPIHandlers.GetObjectLegalHoldHandler
func GetObjectLegalHoldHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// GetObjectHandler exposes minio's cmd.objectAPIHandlers.GetObjectHandler
//
//nolint: golint
//go:linkname GetObjectHandler storj.io/minio/cmd.objectAPIHandlers.GetObjectHandler
func GetObjectHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// CopyObjectHandler exposes minio's cmd.objectAPIHandlers.CopyObjectHandler
//
//nolint: golint
//go:linkname CopyObjectHandler storj.io/minio/cmd.objectAPIHandlers.CopyObjectHandler
func CopyObjectHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// PutObjectRetentionHandler exposes minio's cmd.objectAPIHandlers.PutObjectRetentionHandler
//
//nolint: golint
//go:linkname PutObjectRetentionHandler storj.io/minio/cmd.objectAPIHandlers.PutObjectRetentionHandler
func PutObjectRetentionHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// PutObjectLegalHoldHandler exposes minio's cmd.objectAPIHandlers.PutObjectLegalHoldHandler
//
//nolint: golint
//go:linkname PutObjectLegalHoldHandler storj.io/minio/cmd.objectAPIHandlers.PutObjectLegalHoldHandler
func PutObjectLegalHoldHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// PutObjectHandler exposes minio's cmd.objectAPIHandlers.PutObjectHandler
//
//nolint: golint
//go:linkname PutObjectHandler storj.io/minio/cmd.objectAPIHandlers.PutObjectHandler
func PutObjectHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// DeleteObjectHandler exposes minio's cmd.objectAPIHandlers.DeleteObjectHandler
//
//nolint: golint
//go:linkname DeleteObjectHandler storj.io/minio/cmd.objectAPIHandlers.DeleteObjectHandler
func DeleteObjectHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// GetBucketLocationHandler exposes minio's cmd.objectAPIHandlers.GetBucketLocationHandler
//
//nolint: golint
//go:linkname GetBucketLocationHandler storj.io/minio/cmd.objectAPIHandlers.GetBucketLocationHandler
func GetBucketLocationHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// GetBucketPolicyHandler exposes minio's cmd.objectAPIHandlers.GetBucketPolicyHandler
//
//nolint: golint
//go:linkname GetBucketPolicyHandler storj.io/minio/cmd.objectAPIHandlers.GetBucketPolicyHandler
func GetBucketPolicyHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// GetBucketLifecycleHandler exposes minio's cmd.objectAPIHandlers.GetBucketLifecycleHandler
//
//nolint: golint
//go:linkname GetBucketLifecycleHandler storj.io/minio/cmd.objectAPIHandlers.GetBucketLifecycleHandler
func GetBucketLifecycleHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// GetBucketEncryptionHandler exposes minio's cmd.objectAPIHandlers.GetBucketEncryptionHandler
//
//nolint: golint
//go:linkname GetBucketEncryptionHandler storj.io/minio/cmd.objectAPIHandlers.GetBucketEncryptionHandler
func GetBucketEncryptionHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// GetBucketObjectLockConfigHandler exposes minio's cmd.objectAPIHandlers.GetBucketObjectLockConfigHandler
//
//nolint: golint
//go:linkname GetBucketObjectLockConfigHandler storj.io/minio/cmd.objectAPIHandlers.GetBucketObjectLockConfigHandler
func GetBucketObjectLockConfigHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// GetBucketReplicationConfigHandler exposes minio's cmd.objectAPIHandlers.GetBucketReplicationConfigHandler
//
//nolint: golint
//go:linkname GetBucketReplicationConfigHandler storj.io/minio/cmd.objectAPIHandlers.GetBucketReplicationConfigHandler
func GetBucketReplicationConfigHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// GetBucketVersioningHandler exposes minio's cmd.objectAPIHandlers.GetBucketVersioningHandler
//
//nolint: golint
//go:linkname GetBucketVersioningHandler storj.io/minio/cmd.objectAPIHandlers.GetBucketVersioningHandler
func GetBucketVersioningHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// GetBucketNotificationHandler exposes minio's cmd.objectAPIHandlers.GetBucketNotificationHandler
//
//nolint: golint
//go:linkname GetBucketNotificationHandler storj.io/minio/cmd.objectAPIHandlers.GetBucketNotificationHandler
func GetBucketNotificationHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// ListenNotificationHandler exposes minio's cmd.objectAPIHandlers.ListenNotificationHandler
//
//nolint: golint
//go:linkname ListenNotificationHandler storj.io/minio/cmd.objectAPIHandlers.ListenNotificationHandler
func ListenNotificationHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// GetBucketACLHandler exposes minio's cmd.objectAPIHandlers.GetBucketACLHandler
//
//nolint: golint
//go:linkname GetBucketACLHandler storj.io/minio/cmd.objectAPIHandlers.GetBucketACLHandler
func GetBucketACLHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// PutBucketACLHandler exposes minio's cmd.objectAPIHandlers.PutBucketACLHandler
//
//nolint: golint
//go:linkname PutBucketACLHandler storj.io/minio/cmd.objectAPIHandlers.PutBucketACLHandler
func PutBucketACLHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// GetBucketCorsHandler exposes minio's cmd.objectAPIHandlers.GetBucketCorsHandler
//
//nolint: golint
//go:linkname GetBucketCorsHandler storj.io/minio/cmd.objectAPIHandlers.GetBucketCorsHandler
func GetBucketCorsHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// GetBucketWebsiteHandler exposes minio's cmd.objectAPIHandlers.GetBucketWebsiteHandler
//
//nolint: golint
//go:linkname GetBucketWebsiteHandler storj.io/minio/cmd.objectAPIHandlers.GetBucketWebsiteHandler
func GetBucketWebsiteHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// GetBucketAccelerateHandler exposes minio's cmd.objectAPIHandlers.GetBucketAccelerateHandler
//
//nolint: golint
//go:linkname GetBucketAccelerateHandler storj.io/minio/cmd.objectAPIHandlers.GetBucketAccelerateHandler
func GetBucketAccelerateHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// GetBucketRequestPaymentHandler exposes minio's cmd.objectAPIHandlers.GetBucketRequestPaymentHandler
//
//nolint: golint
//go:linkname GetBucketRequestPaymentHandler storj.io/minio/cmd.objectAPIHandlers.GetBucketRequestPaymentHandler
func GetBucketRequestPaymentHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// GetBucketLoggingHandler exposes minio's cmd.objectAPIHandlers.GetBucketLoggingHandler
//
//nolint: golint
//go:linkname GetBucketLoggingHandler storj.io/minio/cmd.objectAPIHandlers.GetBucketLoggingHandler
func GetBucketLoggingHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// GetBucketTaggingHandler exposes minio's cmd.objectAPIHandlers.GetBucketTaggingHandler
//
//nolint: golint
//go:linkname GetBucketTaggingHandler storj.io/minio/cmd.objectAPIHandlers.GetBucketTaggingHandler
func GetBucketTaggingHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// DeleteBucketWebsiteHandler exposes minio's cmd.objectAPIHandlers.DeleteBucketWebsiteHandler
//
//nolint: golint
//go:linkname DeleteBucketWebsiteHandler storj.io/minio/cmd.objectAPIHandlers.DeleteBucketWebsiteHandler
func DeleteBucketWebsiteHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// DeleteBucketTaggingHandler exposes minio's cmd.objectAPIHandlers.DeleteBucketTaggingHandler
//
//nolint: golint
//go:linkname DeleteBucketTaggingHandler storj.io/minio/cmd.objectAPIHandlers.DeleteBucketWebsiteHandler
func DeleteBucketTaggingHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// ListMultipartUploadsHandler exposes minio's cmd.objectAPIHandlers.ListMultipartUploadsHandler
//
//nolint: golint
//go:linkname ListMultipartUploadsHandler storj.io/minio/cmd.objectAPIHandlers.ListMultipartUploadsHandler
func ListMultipartUploadsHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// ListObjectsV2MHandler exposes minio's cmd.objectAPIHandlers.ListObjectsV2MHandler
//
//nolint: golint
//go:linkname ListObjectsV2MHandler storj.io/minio/cmd.objectAPIHandlers.ListObjectsV2MHandler
func ListObjectsV2MHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// ListObjectsV2Handler exposes minio's cmd.objectAPIHandlers.ListObjectsV2Handler
//
//nolint: golint
//go:linkname ListObjectsV2Handler storj.io/minio/cmd.objectAPIHandlers.ListObjectsV2Handler
func ListObjectsV2Handler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// ListObjectVersionsHandler exposes minio's cmd.objectAPIHandlers.ListObjectVersionsHandler
//
//nolint: golint
//go:linkname ListObjectVersionsHandler storj.io/minio/cmd.objectAPIHandlers.ListObjectVersionsHandler
func ListObjectVersionsHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// ListObjectsV1Handler exposes minio's cmd.objectAPIHandlers.ListObjectsV1Handler
//
//nolint: golint
//go:linkname ListObjectsV1Handler storj.io/minio/cmd.objectAPIHandlers.ListObjectsV1Handler
func ListObjectsV1Handler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// PutBucketLifecycleHandler exposes minio's cmd.objectAPIHandlers.PutBucketLifecycleHandler
//
//nolint: golint
//go:linkname PutBucketLifecycleHandler storj.io/minio/cmd.objectAPIHandlers.PutBucketLifecycleHandler
func PutBucketLifecycleHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// PutBucketReplicationConfigHandler exposes minio's cmd.objectAPIHandlers.PutBucketReplicationConfigHandler
//
//nolint: golint
//go:linkname PutBucketReplicationConfigHandler storj.io/minio/cmd.objectAPIHandlers.PutBucketReplicationConfigHandler
func PutBucketReplicationConfigHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// PutBucketEncryptionHandler exposes minio's cmd.objectAPIHandlers.PutBucketEncryptionHandler
//
//nolint: golint
//go:linkname PutBucketEncryptionHandler storj.io/minio/cmd.objectAPIHandlers.PutBucketEncryptionHandler
func PutBucketEncryptionHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// PutBucketPolicyHandler exposes minio's cmd.objectAPIHandlers.PutBucketPolicyHandler
//
//nolint: golint
//go:linkname PutBucketPolicyHandler storj.io/minio/cmd.objectAPIHandlers.PutBucketPolicyHandler
func PutBucketPolicyHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// PutBucketObjectLockConfigHandler exposes minio's cmd.objectAPIHandlers.PutBucketObjectLockConfigHandler
//
//nolint: golint
//go:linkname PutBucketObjectLockConfigHandler storj.io/minio/cmd.objectAPIHandlers.PutBucketObjectLockConfigHandler
func PutBucketObjectLockConfigHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// PutBucketTaggingHandler exposes minio's cmd.objectAPIHandlers.PutBucketTaggingHandler
//
//nolint: golint
//go:linkname PutBucketTaggingHandler storj.io/minio/cmd.objectAPIHandlers.PutBucketTaggingHandler
func PutBucketTaggingHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// PutBucketVersioningHandler exposes minio's cmd.objectAPIHandlers.PutBucketVersioningHandler
//
//nolint: golint
//go:linkname PutBucketVersioningHandler storj.io/minio/cmd.objectAPIHandlers.PutBucketVersioningHandler
func PutBucketVersioningHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// PutBucketNotificationHandler exposes minio's cmd.objectAPIHandlers.PutBucketNotificationHandler
//
//nolint: golint
//go:linkname PutBucketNotificationHandler storj.io/minio/cmd.objectAPIHandlers.PutBucketNotificationHandler
func PutBucketNotificationHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// PutBucketHandler exposes minio's cmd.objectAPIHandlers.PutBucketHandler
//
//nolint: golint
//go:linkname PutBucketHandler storj.io/minio/cmd.objectAPIHandlers.PutBucketHandler
func PutBucketHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// HeadBucketHandler exposes minio's cmd.objectAPIHandlers.HeadBucketHandler
//
//nolint: golint
//go:linkname HeadBucketHandler storj.io/minio/cmd.objectAPIHandlers.HeadBucketHandler
func HeadBucketHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// PostPolicyBucketHandler exposes minio's cmd.objectAPIHandlers.PostPolicyBucketHandler
//
//nolint: golint
//go:linkname PostPolicyBucketHandler storj.io/minio/cmd.objectAPIHandlers.PostPolicyBucketHandler
func PostPolicyBucketHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// DeleteMultipleObjectsHandler exposes minio's cmd.objectAPIHandlers.DeleteMultipleObjectsHandler
//
//nolint: golint
//go:linkname DeleteMultipleObjectsHandler storj.io/minio/cmd.objectAPIHandlers.DeleteMultipleObjectsHandler
func DeleteMultipleObjectsHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// DeleteBucketPolicyHandler exposes minio's cmd.objectAPIHandlers.DeleteBucketPolicyHandler
//
//nolint: golint
//go:linkname DeleteBucketPolicyHandler storj.io/minio/cmd.objectAPIHandlers.DeleteBucketPolicyHandler
func DeleteBucketPolicyHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// DeleteBucketReplicationConfigHandler exposes minio's cmd.objectAPIHandlers.DeleteBucketReplicationConfigHandler
//
//nolint: golint
//go:linkname DeleteBucketReplicationConfigHandler storj.io/minio/cmd.objectAPIHandlers.DeleteBucketReplicationConfigHandler
func DeleteBucketReplicationConfigHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// DeleteBucketLifecycleHandler exposes minio's cmd.objectAPIHandlers.DeleteBucketLifecycleHandler
//
//nolint: golint
//go:linkname DeleteBucketLifecycleHandler storj.io/minio/cmd.objectAPIHandlers.DeleteBucketLifecycleHandler
func DeleteBucketLifecycleHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// DeleteBucketEncryptionHandler exposes minio's cmd.objectAPIHandlers.DeleteBucketEncryptionHandler
//
//nolint: golint
//go:linkname DeleteBucketEncryptionHandler storj.io/minio/cmd.objectAPIHandlers.DeleteBucketEncryptionHandler
func DeleteBucketEncryptionHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// DeleteBucketHandler exposes minio's cmd.objectAPIHandlers.DeleteBucketHandler
//
//nolint: golint
//go:linkname DeleteBucketHandler storj.io/minio/cmd.objectAPIHandlers.DeleteBucketHandler
func DeleteBucketHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// PostRestoreObjectHandler exposes minio's cmd.objectAPIHandlers.PostRestoreObjectHandler
//
//nolint: golint
//go:linkname PostRestoreObjectHandler storj.io/minio/cmd.objectAPIHandlers.PostRestoreObjectHandler
func PostRestoreObjectHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)

// ListBucketsHandler exposes minio's cmd.objectAPIHandlers.ListBucketsHandler
//
//nolint: golint
//go:linkname ListBucketsHandler storj.io/minio/cmd.objectAPIHandlers.ListBucketsHandler
func ListBucketsHandler(objectAPIHandlers, http.ResponseWriter, *http.Request)
