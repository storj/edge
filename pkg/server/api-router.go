// Copyright (c) 2015-2021 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// This code is a derivative work.
// Derived changes Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/minio/minio/cmd"

	"storj.io/gateway-mt/pkg/minio"
)

const (
	// SlashSeparator - slash separator.
	SlashSeparator = "/"
	// ContentType is "Content-Type".
	ContentType = "Content-Type"
	// AmzCopySource is "X-Amz-Copy-Source".
	AmzCopySource = "X-Amz-Copy-Source"
	// AmzRequestID is "x-amz-request-id".
	AmzRequestID = "x-amz-request-id"
	// AmzSnowballExtract is "X-Amz-Meta-Snowball-Auto-Extract".
	AmzSnowballExtract = "X-Amz-Meta-Snowball-Auto-Extract"
)

// RegisterAPIRouter - registers S3 compatible APIs.
func RegisterAPIRouter(router *mux.Router, objectAPI func() cmd.ObjectLayer, domainNames []string) {
	// Initialize API.
	api := cmd.ObjectAPIHandlers{ObjectAPI: objectAPI}

	// API Router
	apiRouter := router.PathPrefix(SlashSeparator).Subrouter()

	var routers []*mux.Router
	for _, domainName := range domainNames {
		routers = append(routers, apiRouter.Host("{bucket:.+}."+domainName).Subrouter())
	}
	routers = append(routers, apiRouter.PathPrefix("/{bucket}").Subrouter())

	// Note that the commented routes below correspond to route that we previously removed
	// from Minio.  However, we may want to add these back, so they have been left commented.

	for _, router := range routers {
		// minio.RejectUnsupportedAPIs(router)

		// Object operations
		// HeadObject
		router.Methods(http.MethodHead).Path("/{object:.+}").HandlerFunc(
			collectAPIStats("headobject", api.HeadObjectHandler))
		// CopyObjectPart
		router.Methods(http.MethodPut).Path("/{object:.+}").
			HeadersRegexp(AmzCopySource, ".*?(\\/|%2F).*?").
			HandlerFunc(collectAPIStats("copyobjectpart", api.CopyObjectPartHandler)).
			Queries("partNumber", "{partNumber:[0-9]+}", "uploadId", "{uploadId:.*}")
		// PutObjectPart
		router.Methods(http.MethodPut).Path("/{object:.+}").HandlerFunc(
			collectAPIStats("putobjectpart", api.PutObjectPartHandler)).Queries("partNumber", "{partNumber:[0-9]+}", "uploadId", "{uploadId:.*}")
		// ListObjectParts
		router.Methods(http.MethodGet).Path("/{object:.+}").HandlerFunc(
			collectAPIStats("listobjectparts", api.ListObjectPartsHandler)).Queries("uploadId", "{uploadId:.*}")
		// CompleteMultipartUpload
		router.Methods(http.MethodPost).Path("/{object:.+}").HandlerFunc(
			collectAPIStats("completemutipartupload", api.CompleteMultipartUploadHandler)).Queries("uploadId", "{uploadId:.*}")
		// NewMultipartUpload
		router.Methods(http.MethodPost).Path("/{object:.+}").HandlerFunc(
			collectAPIStats("newmultipartupload", api.NewMultipartUploadHandler)).Queries("uploads", "")
		// AbortMultipartUpload
		router.Methods(http.MethodDelete).Path("/{object:.+}").HandlerFunc(
			collectAPIStats("abortmultipartupload", api.AbortMultipartUploadHandler)).Queries("uploadId", "{uploadId:.*}")
		// GetObjectACL - this is a dummy call.
		// router.Methods(http.MethodGet).Path("/{object:.+}").HandlerFunc(
		// 	collectAPIStats("getobjectacl", api.GetObjectACLHandler)).Queries("acl", "")
		// PutObjectACL - this is a dummy call.
		// router.Methods(http.MethodPut).Path("/{object:.+}").HandlerFunc(
		// 	collectAPIStats("putobjectacl", api.PutObjectACLHandler)).Queries("acl", "")
		// GetObjectTagging
		router.Methods(http.MethodGet).Path("/{object:.+}").HandlerFunc(
			collectAPIStats("getobjecttagging", api.GetObjectTaggingHandler)).Queries("tagging", "")
		// PutObjectTagging
		router.Methods(http.MethodPut).Path("/{object:.+}").HandlerFunc(
			collectAPIStats("putobjecttagging", api.PutObjectTaggingHandler)).Queries("tagging", "")
		// DeleteObjectTagging
		router.Methods(http.MethodDelete).Path("/{object:.+}").HandlerFunc(
			collectAPIStats("deleteobjecttagging", api.DeleteObjectTaggingHandler)).Queries("tagging", "")
		// SelectObjectContent
		router.Methods(http.MethodPost).Path("/{object:.+}").HandlerFunc(
			collectAPIStats("selectobjectcontent", api.SelectObjectContentHandler)).Queries("select", "").Queries("select-type", "2")
		// GetObjectRetention
		// router.Methods(http.MethodGet).Path("/{object:.+}").HandlerFunc(
		// 	collectAPIStats("getobjectretention", api.GetObjectRetentionHandler)).Queries("retention", "")
		// GetObjectLegalHold
		// router.Methods(http.MethodGet).Path("/{object:.+}").HandlerFunc(
		// 	collectAPIStats("getobjectlegalhold", api.GetObjectLegalHoldHandler)).Queries("legal-hold", "")
		// GetObject
		router.Methods(http.MethodGet).Path("/{object:.+}").HandlerFunc(
			collectAPIStats("getobject", api.GetObjectHandler))
		// CopyObject
		router.Methods(http.MethodPut).Path("/{object:.+}").HeadersRegexp(AmzCopySource, ".*?(\\/|%2F).*?").HandlerFunc(
			collectAPIStats("copyobject", api.CopyObjectHandler))
		// PutObjectRetention
		// router.Methods(http.MethodPut).Path("/{object:.+}").HandlerFunc(
		// 	collectAPIStats("putobjectretention", api.PutObjectRetentionHandler)).Queries("retention", "")
		// PutObjectLegalHold
		// router.Methods(http.MethodPut).Path("/{object:.+}").HandlerFunc(
		// 	collectAPIStats("putobjectlegalhold", api.PutObjectLegalHoldHandler)).Queries("legal-hold", "")

		// PutObject with auto-extract support for zip
		// router.Methods(http.MethodPut).Path("/{object:.+}").HeadersRegexp(AmzSnowballExtract, "true").HandlerFunc(
		// 	collectAPIStats("putobject", api.PutObjectExtractHandler))

		// PutObject
		router.Methods(http.MethodPut).Path("/{object:.+}").HandlerFunc(
			collectAPIStats("putobject", api.PutObjectHandler))

		// DeleteObject
		router.Methods(http.MethodDelete).Path("/{object:.+}").HandlerFunc(
			collectAPIStats("deleteobject", api.DeleteObjectHandler))

		// PostRestoreObject
		router.Methods(http.MethodPost).Path("/{object:.+}").HandlerFunc(
			collectAPIStats("restoreobject", api.PostRestoreObjectHandler)).Queries("restore", "")

		// Bucket operations
		// GetBucketLocation
		router.Methods(http.MethodGet).HandlerFunc(
			collectAPIStats("getbucketlocation", api.GetBucketLocationHandler)).Queries("location", "")
		// GetBucketPolicy
		// router.Methods(http.MethodGet).HandlerFunc(
		// 	collectAPIStats("getbucketpolicy", api.GetBucketPolicyHandler)).Queries("policy", "")
		// GetBucketLifecycle
		// router.Methods(http.MethodGet).HandlerFunc(
		// 	collectAPIStats("getbucketlifecycle", api.GetBucketLifecycleHandler)).Queries("lifecycle", "")
		// GetBucketEncryption
		// router.Methods(http.MethodGet).HandlerFunc(
		// 	collectAPIStats("getbucketencryption", api.GetBucketEncryptionHandler)).Queries("encryption", "")
		// GetBucketObjectLockConfig
		// router.Methods(http.MethodGet).HandlerFunc(
		// 	collectAPIStats("getbucketobjectlockconfiguration", api.GetBucketObjectLockConfigHandler)).Queries("object-lock", "")
		// GetBucketReplicationConfig
		// router.Methods(http.MethodGet).HandlerFunc(
		// 	collectAPIStats("getbucketreplicationconfiguration", api.GetBucketReplicationConfigHandler)).Queries("replication", "")
		// GetBucketVersioning
		// router.Methods(http.MethodGet).HandlerFunc(
		// 	collectAPIStats("getbucketversioning", api.GetBucketVersioningHandler)).Queries("versioning", "")
		// GetBucketNotification
		// router.Methods(http.MethodGet).HandlerFunc(
		// 	collectAPIStats("getbucketnotification", api.GetBucketNotificationHandler)).Queries("notification", "")
		// ListenNotification
		// router.Methods(http.MethodGet).HandlerFunc(
		// 	collectAPIStats("listennotification", api.ListenNotificationHandler)).Queries("events", "{events:.*}")

		// Dummy Bucket Calls
		// GetBucketACL -- this is a dummy call.
		// router.Methods(http.MethodGet).HandlerFunc(
		// 	collectAPIStats("getbucketacl", api.GetBucketACLHandler)).Queries("acl", "")
		// PutBucketACL -- this is a dummy call.
		// router.Methods(http.MethodPut).HandlerFunc(
		// 	collectAPIStats("putbucketacl", api.PutBucketACLHandler)).Queries("acl", "")
		// GetBucketCors - this is a dummy call.
		router.Methods(http.MethodGet).HandlerFunc(
			collectAPIStats("getbucketcors", api.GetBucketCorsHandler)).Queries("cors", "")
		// GetBucketWebsiteHandler - this is a dummy call.
		router.Methods(http.MethodGet).HandlerFunc(
			collectAPIStats("getbucketwebsite", api.GetBucketWebsiteHandler)).Queries("website", "")
		// GetBucketAccelerateHandler - this is a dummy call.
		router.Methods(http.MethodGet).HandlerFunc(
			collectAPIStats("getbucketaccelerate", api.GetBucketAccelerateHandler)).Queries("accelerate", "")
		// GetBucketRequestPaymentHandler - this is a dummy call.
		router.Methods(http.MethodGet).HandlerFunc(
			collectAPIStats("getbucketrequestpayment", api.GetBucketRequestPaymentHandler)).Queries("requestPayment", "")
		// GetBucketLoggingHandler - this is a dummy call.
		router.Methods(http.MethodGet).HandlerFunc(
			collectAPIStats("getbucketlogging", api.GetBucketLoggingHandler)).Queries("logging", "")
		// GetBucketTaggingHandler
		// router.Methods(http.MethodGet).HandlerFunc(
		// 	collectAPIStats("getbuckettagging", api.GetBucketTaggingHandler)).Queries("tagging", "")
		// DeleteBucketWebsiteHandler
		router.Methods(http.MethodDelete).HandlerFunc(
			collectAPIStats("deletebucketwebsite", api.DeleteBucketWebsiteHandler)).Queries("website", "")
		// DeleteBucketTaggingHandler
		// router.Methods(http.MethodDelete).HandlerFunc(
		// 	collectAPIStats("deletebuckettagging", api.DeleteBucketTaggingHandler)).Queries("tagging", "")

		// ListMultipartUploads
		router.Methods(http.MethodGet).HandlerFunc(
			collectAPIStats("listmultipartuploads", api.ListMultipartUploadsHandler)).Queries("uploads", "")
		// ListObjectsV2M
		router.Methods(http.MethodGet).HandlerFunc(
			collectAPIStats("listobjectsv2M", api.ListObjectsV2MHandler)).Queries("list-type", "2", "metadata", "true")
		// ListObjectsV2
		router.Methods(http.MethodGet).HandlerFunc(
			collectAPIStats("listobjectsv2", api.ListObjectsV2Handler)).Queries("list-type", "2")
		// ListObjectVersions
		router.Methods(http.MethodGet).HandlerFunc(
			collectAPIStats("listobjectversions", api.ListObjectVersionsHandler)).Queries("versions", "")
		// GetBucketPolicyStatus
		// router.Methods(http.MethodGet).HandlerFunc(
		// 	collectAPIStats("getpolicystatus", api.GetBucketPolicyStatusHandler)).Queries("policyStatus", "")
		// PutBucketLifecycle
		// router.Methods(http.MethodPut).HandlerFunc(
		// 	collectAPIStats("putbucketlifecycle", api.PutBucketLifecycleHandler)).Queries("lifecycle", "")
		// PutBucketReplicationConfig
		// router.Methods(http.MethodPut).HandlerFunc(
		// 	collectAPIStats("putbucketreplicationconfiguration", api.PutBucketReplicationConfigHandler)).Queries("replication", "")
		// PutBucketEncryption
		// router.Methods(http.MethodPut).HandlerFunc(
		// 	collectAPIStats("putbucketencryption", api.PutBucketEncryptionHandler)).Queries("encryption", "")

		// PutBucketPolicy
		// router.Methods(http.MethodPut).HandlerFunc(
		// 	collectAPIStats("putbucketpolicy", api.PutBucketPolicyHandler)).Queries("policy", "")

		// PutBucketObjectLockConfig
		// router.Methods(http.MethodPut).HandlerFunc(
		// 	collectAPIStats("putbucketobjectlockconfig", api.PutBucketObjectLockConfigHandler)).Queries("object-lock", "")
		// PutBucketTaggingHandler
		// router.Methods(http.MethodPut).HandlerFunc(
		// 	collectAPIStats("putbuckettagging", api.PutBucketTaggingHandler)).Queries("tagging", "")
		// PutBucketVersioning
		// router.Methods(http.MethodPut).HandlerFunc(
		// 	collectAPIStats("putbucketversioning", api.PutBucketVersioningHandler)).Queries("versioning", "")
		// PutBucketNotification
		// router.Methods(http.MethodPut).HandlerFunc(
		// 	collectAPIStats("putbucketnotification", api.PutBucketNotificationHandler)).Queries("notification", "")
		// PutBucket
		router.Methods(http.MethodPut).HandlerFunc(
			collectAPIStats("putbucket", api.PutBucketHandler))
		// HeadBucket
		router.Methods(http.MethodHead).HandlerFunc(
			collectAPIStats("headbucket", api.HeadBucketHandler))
		// PostPolicy
		router.Methods(http.MethodPost).HeadersRegexp(ContentType, "multipart/form-data*").HandlerFunc(
			collectAPIStats("postpolicybucket", api.PostPolicyBucketHandler))
		// DeleteMultipleObjects
		router.Methods(http.MethodPost).HandlerFunc(
			collectAPIStats("deletemultipleobjects", api.DeleteMultipleObjectsHandler)).Queries("delete", "")
		// DeleteBucketPolicy
		// router.Methods(http.MethodDelete).HandlerFunc(
		// 	collectAPIStats("deletebucketpolicy", api.DeleteBucketPolicyHandler)).Queries("policy", "")
		// DeleteBucketReplication
		// router.Methods(http.MethodDelete).HandlerFunc(
		// 	collectAPIStats("deletebucketreplicationconfiguration", api.DeleteBucketReplicationConfigHandler)).Queries("replication", "")
		// DeleteBucketLifecycle
		// router.Methods(http.MethodDelete).HandlerFunc(
		// 	collectAPIStats("deletebucketlifecycle", api.DeleteBucketLifecycleHandler)).Queries("lifecycle", "")
		// DeleteBucketEncryption
		// router.Methods(http.MethodDelete).HandlerFunc(
		// 	collectAPIStats("deletebucketencryption", api.DeleteBucketEncryptionHandler)).Queries("encryption", "")
		// DeleteBucket
		router.Methods(http.MethodDelete).HandlerFunc(
			collectAPIStats("deletebucket", api.DeleteBucketHandler))
		// MinIO extension API for replication.
		//
		// GetBucketReplicationMetrics
		// router.Methods(http.MethodGet).HandlerFunc(
		// 	collectAPIStats("getbucketreplicationmetrics", api.GetBucketReplicationMetricsHandler)).Queries("replication-metrics", "")

		// S3 ListObjectsV1 (Legacy)
		router.Methods(http.MethodGet).HandlerFunc(
			collectAPIStats("listobjectsv1", api.ListObjectsV1Handler))

	}

	// Root operation

	// ListenNotification
	// apiRouter.Methods(http.MethodGet).Path(SlashSeparator).HandlerFunc(
	// 	collectAPIStats("listennotification", api.ListenNotificationHandler)).Queries("events", "{events:.*}")

	// ListBuckets
	apiRouter.Methods(http.MethodGet).Path(SlashSeparator).HandlerFunc(
		collectAPIStats("listbuckets", api.ListBucketsHandler))

	// S3 browser with signature v4 adds '//' for ListBuckets request, so rather
	// than failing with UnknownAPIRequest we simply handle it for now.
	apiRouter.Methods(http.MethodGet).Path(SlashSeparator + SlashSeparator).HandlerFunc(
		collectAPIStats("listbuckets", api.ListBucketsHandler))

	// If none of the routes match add default error handler routes.
	apiRouter.NotFoundHandler = collectAPIStats("notfound", errorResponseHandler)
	apiRouter.MethodNotAllowedHandler = collectAPIStats("methodnotallowed", methodNotAllowedHandler("S3"))

}

func collectAPIStats(route string, f http.HandlerFunc) http.HandlerFunc {
	// TODO: This naming convention is what Minio uses.  Revisit this and see if we
	// can use this interface but preserve some features from metrics.go and from
	// "gopkg.in/webhelp.v1/whlog".
	return func(w http.ResponseWriter, r *http.Request) {
		f.ServeHTTP(w, r)
	}
}

func methodNotAllowedHandler(api string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		code := "XMinio" + api + "VersionMismatch"
		minio.WriteErrorResponseString(r.Context(), w, cmd.APIError{
			Code:           code,
			Description:    "Not allowed (" + r.Method + " " + r.URL.String() + " on " + api + " API)",
			HTTPStatusCode: http.StatusMethodNotAllowed,
		}, r.URL)
	}
}

// If none of the http routes match respond with appropriate errors.
func errorResponseHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		return
	}

	desc := fmt.Sprintf("Unknown API request at %s", r.URL.Path)
	minio.WriteErrorResponse(r.Context(), w, cmd.APIError{
		Code:           "XMinioUnknownAPIRequest",
		Description:    desc,
		HTTPStatusCode: http.StatusBadRequest,
	}, r.URL)
}
