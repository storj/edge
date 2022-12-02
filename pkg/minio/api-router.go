// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package minio

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"

	"storj.io/gateway-mt/pkg/server/gw"
	"storj.io/gateway-mt/pkg/server/middleware"
	"storj.io/minio/cmd"
	xhttp "storj.io/minio/cmd/http"
)

// RegisterAPIRouter - registers S3 compatible APIs.
func RegisterAPIRouter(router *mux.Router, layer *gw.MultiTenancyLayer, domainNames []string, concurrentAllowed uint, corsAllowedOrigins []string) {
	api := objectAPIHandlersWrapper{cmd.ObjectAPIHandlers{
		ObjectAPI: func() cmd.ObjectLayer { return layer },
		CacheAPI:  func() cmd.CacheObjectLayer { return nil },
	}, corsAllowedOrigins}

	// limit the conccurrency of uploads and downloads per macaroon head
	limit := middleware.NewMacaroonLimiter(concurrentAllowed,
		func(w http.ResponseWriter, r *http.Request) {
			err := cmd.APIError{
				Code:           "SlowDown",                 // necessary to return a RetryAfter header
				HTTPStatusCode: http.StatusTooManyRequests, // Minio's ErrSlowDown yields a 503, but 429 seems clearer
				Description:    fmt.Sprintf("Only %d concurrent uploads or downloads are allowed per credential", concurrentAllowed),
			}
			cmd.WriteErrorResponse(r.Context(), w, err, r.URL, false)
		},
	).Limit

	apiRouter := router.PathPrefix(cmd.SlashSeparator).Subrouter()

	var routers []*mux.Router
	for _, domainName := range domainNames {
		routers = append(routers, apiRouter.Host("{bucket:.+}."+domainName).Subrouter())
	}

	routers = append(routers, apiRouter.PathPrefix("/{bucket}").Subrouter())

	for _, bucket := range routers {
		// Object operations
		// HeadObject
		bucket.Methods(http.MethodHead).Path("/{object:.+}").HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("headobject", cmd.HTTPTraceAll(api.HeadObjectHandler))))
		// CopyObjectPart
		bucket.Methods(http.MethodPut).Path("/{object:.+}").
			HeadersRegexp(xhttp.AmzCopySource, ".*?(\\/|%2F).*?").
			HandlerFunc(cmd.MaxClients(cmd.CollectAPIStats("copyobjectpart", cmd.HTTPTraceAll(api.CopyObjectPartHandler)))).
			Queries("partNumber", "{partNumber:[0-9]+}", "uploadId", "{uploadId:.*}")
		// PutObjectPart
		bucket.Methods(http.MethodPut).Path("/{object:.+}").Handler(
			limit(cmd.MaxClients(cmd.CollectAPIStats("putobjectpart", cmd.HTTPTraceHdrs(api.PutObjectPartHandler))))).Queries("partNumber", "{partNumber:[0-9]+}", "uploadId", "{uploadId:.*}")
		// ListObjectParts
		bucket.Methods(http.MethodGet).Path("/{object:.+}").HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("listobjectparts", cmd.HTTPTraceAll(api.ListObjectPartsHandler)))).Queries("uploadId", "{uploadId:.*}")
		// CompleteMultipartUpload
		bucket.Methods(http.MethodPost).Path("/{object:.+}").HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("completemutipartupload", cmd.HTTPTraceAll(api.CompleteMultipartUploadHandler)))).Queries("uploadId", "{uploadId:.*}")
		// NewMultipartUpload
		bucket.Methods(http.MethodPost).Path("/{object:.+}").HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("newmultipartupload", cmd.HTTPTraceAll(api.NewMultipartUploadHandler)))).Queries("uploads", "")
		// AbortMultipartUpload
		bucket.Methods(http.MethodDelete).Path("/{object:.+}").HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("abortmultipartupload", cmd.HTTPTraceAll(api.AbortMultipartUploadHandler)))).Queries("uploadId", "{uploadId:.*}")
		// GetObjectACL - this is a dummy call.
		bucket.Methods(http.MethodGet).Path("/{object:.+}").HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("getobjectacl", cmd.HTTPTraceHdrs(api.GetObjectACLHandler)))).Queries("acl", "")
		// PutObjectACL - this is a dummy call.
		bucket.Methods(http.MethodPut).Path("/{object:.+}").HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("putobjectacl", cmd.HTTPTraceHdrs(api.PutObjectACLHandler)))).Queries("acl", "")
		// GetObjectTagging
		bucket.Methods(http.MethodGet).Path("/{object:.+}").HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("getobjecttagging", cmd.HTTPTraceHdrs(api.GetObjectTaggingHandler)))).Queries("tagging", "")
		// PutObjectTagging
		bucket.Methods(http.MethodPut).Path("/{object:.+}").HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("putobjecttagging", cmd.HTTPTraceHdrs(api.PutObjectTaggingHandler)))).Queries("tagging", "")
		// DeleteObjectTagging
		bucket.Methods(http.MethodDelete).Path("/{object:.+}").HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("deleteobjecttagging", cmd.HTTPTraceHdrs(api.DeleteObjectTaggingHandler)))).Queries("tagging", "")
		// SelectObjectContent
		bucket.Methods(http.MethodPost).Path("/{object:.+}").HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("selectobjectcontent", cmd.HTTPTraceHdrs(api.SelectObjectContentHandler)))).Queries("select", "").Queries("select-type", "2")
		// GetObjectRetention
		bucket.Methods(http.MethodGet).Path("/{object:.+}").HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("getobjectretention", cmd.HTTPTraceAll(api.GetObjectRetentionHandler)))).Queries("retention", "")
		// GetObjectLegalHold
		bucket.Methods(http.MethodGet).Path("/{object:.+}").HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("getobjectlegalhold", cmd.HTTPTraceAll(api.GetObjectLegalHoldHandler)))).Queries("legal-hold", "")
		// GetObject
		bucket.Methods(http.MethodGet).Path("/{object:.+}").Handler(
			limit(cmd.MaxClients(cmd.CollectAPIStats("getobject", cmd.HTTPTraceHdrs(api.GetObjectHandler)))))
		// CopyObject
		bucket.Methods(http.MethodPut).Path("/{object:.+}").HeadersRegexp(xhttp.AmzCopySource, ".*?(\\/|%2F).*?").
			HandlerFunc(cmd.MaxClients(cmd.CollectAPIStats("copyobject", cmd.HTTPTraceAll(api.CopyObjectHandler))))
		// PutObjectRetention
		bucket.Methods(http.MethodPut).Path("/{object:.+}").HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("putobjectretention", cmd.HTTPTraceAll(api.PutObjectRetentionHandler)))).Queries("retention", "")
		// PutObjectLegalHold
		bucket.Methods(http.MethodPut).Path("/{object:.+}").HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("putobjectlegalhold", cmd.HTTPTraceAll(api.PutObjectLegalHoldHandler)))).Queries("legal-hold", "")

		// PutObject
		bucket.Methods(http.MethodPut).Path("/{object:.+}").Handler(
			limit(cmd.MaxClients(cmd.CollectAPIStats("putobject", cmd.HTTPTraceHdrs(api.PutObjectHandler)))))
		// DeleteObject
		bucket.Methods(http.MethodDelete).Path("/{object:.+}").HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("deleteobject", cmd.HTTPTraceAll(api.DeleteObjectHandler))))

		// Bucket operations
		// GetBucketLocation
		bucket.Methods(http.MethodGet).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("getbucketlocation", cmd.HTTPTraceAll(api.GetBucketLocationHandler)))).Queries("location", "")
		// GetBucketPolicy
		bucket.Methods(http.MethodGet).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("getbucketpolicy", cmd.HTTPTraceAll(api.GetBucketPolicyHandler)))).Queries("policy", "")
		// GetBucketLifecycle
		bucket.Methods(http.MethodGet).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("getbucketlifecycle", cmd.HTTPTraceAll(api.GetBucketLifecycleHandler)))).Queries("lifecycle", "")
		// GetBucketEncryption
		bucket.Methods(http.MethodGet).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("getbucketencryption", cmd.HTTPTraceAll(api.GetBucketEncryptionHandler)))).Queries("encryption", "")
		// GetBucketObjectLockConfig
		bucket.Methods(http.MethodGet).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("getbucketobjectlockconfiguration", cmd.HTTPTraceAll(api.GetBucketObjectLockConfigHandler)))).Queries("object-lock", "")
		// GetBucketReplicationConfig
		bucket.Methods(http.MethodGet).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("getbucketreplicationconfiguration", cmd.HTTPTraceAll(api.GetBucketReplicationConfigHandler)))).Queries("replication", "")

		// GetBucketVersioning
		bucket.Methods(http.MethodGet).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("getbucketversioning", cmd.HTTPTraceAll(api.GetBucketVersioningHandler)))).Queries("versioning", "")
		// GetBucketNotification
		bucket.Methods(http.MethodGet).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("getbucketnotification", cmd.HTTPTraceAll(api.GetBucketNotificationHandler)))).Queries("notification", "")
		// ListenNotification
		bucket.Methods(http.MethodGet).HandlerFunc(cmd.CollectAPIStats("listennotification", cmd.HTTPTraceAll(api.ListenNotificationHandler))).Queries("events", "{events:.*}")

		// Dummy Bucket Calls
		// GetBucketACL -- this is a dummy call.
		bucket.Methods(http.MethodGet).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("getbucketacl", cmd.HTTPTraceAll(api.GetBucketACLHandler)))).Queries("acl", "")
		// PutBucketACL -- this is a dummy call.
		bucket.Methods(http.MethodPut).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("putbucketacl", cmd.HTTPTraceAll(api.PutBucketACLHandler)))).Queries("acl", "")
		// GetBucketCors - this is a dummy call.
		bucket.Methods(http.MethodGet).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("getbucketcors", cmd.HTTPTraceAll(api.GetBucketCorsHandler)))).Queries("cors", "")
		// PutBucketCors - this is a dummy call.
		bucket.Methods(http.MethodPut).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("putbucketcors", cmd.HTTPTraceAll(api.PutBucketCorsHandler)))).Queries("cors", "")
		// DeleteBucketCors - this is a dummy call.
		bucket.Methods(http.MethodDelete).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("deletebucketcors", cmd.HTTPTraceAll(api.DeleteBucketCorsHandler)))).Queries("cors", "")
		// GetBucketWebsiteHandler - this is a dummy call.
		bucket.Methods(http.MethodGet).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("getbucketwebsite", cmd.HTTPTraceAll(api.GetBucketWebsiteHandler)))).Queries("website", "")
		// GetBucketAccelerateHandler - this is a dummy call.
		bucket.Methods(http.MethodGet).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("getbucketaccelerate", cmd.HTTPTraceAll(api.GetBucketAccelerateHandler)))).Queries("accelerate", "")
		// GetBucketRequestPaymentHandler - this is a dummy call.
		bucket.Methods(http.MethodGet).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("getbucketrequestpayment", cmd.HTTPTraceAll(api.GetBucketRequestPaymentHandler)))).Queries("requestPayment", "")
		// GetBucketLoggingHandler - this is a dummy call.
		bucket.Methods(http.MethodGet).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("getbucketlogging", cmd.HTTPTraceAll(api.GetBucketLoggingHandler)))).Queries("logging", "")
		// GetBucketLifecycleHandler - this is a dummy call.
		bucket.Methods(http.MethodGet).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("getbucketlifecycle", cmd.HTTPTraceAll(api.GetBucketLifecycleHandler)))).Queries("lifecycle", "")
		// GetBucketTaggingHandler
		bucket.Methods(http.MethodGet).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("getbuckettagging", cmd.HTTPTraceAll(api.GetBucketTaggingHandler)))).Queries("tagging", "")
		// DeleteBucketWebsiteHandler
		bucket.Methods(http.MethodDelete).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("deletebucketwebsite", cmd.HTTPTraceAll(api.DeleteBucketWebsiteHandler)))).Queries("website", "")
		// DeleteBucketTaggingHandler
		bucket.Methods(http.MethodDelete).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("deletebuckettagging", cmd.HTTPTraceAll(api.DeleteBucketTaggingHandler)))).Queries("tagging", "")

		// ListMultipartUploads
		bucket.Methods(http.MethodGet).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("listmultipartuploads", cmd.HTTPTraceAll(api.ListMultipartUploadsHandler)))).Queries("uploads", "")
		// ListObjectsV2M
		bucket.Methods(http.MethodGet).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("listobjectsv2M", cmd.HTTPTraceAll(api.ListObjectsV2MHandler)))).Queries("list-type", "2", "metadata", "true")
		// ListObjectsV2
		bucket.Methods(http.MethodGet).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("listobjectsv2", cmd.HTTPTraceAll(api.ListObjectsV2Handler)))).Queries("list-type", "2")
		// ListObjectVersions
		bucket.Methods(http.MethodGet).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("listobjectversions", cmd.HTTPTraceAll(api.ListObjectVersionsHandler)))).Queries("versions", "")
		// ListObjectsV1 (Legacy)
		bucket.Methods(http.MethodGet).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("listobjectsv1", cmd.HTTPTraceAll(api.ListObjectsV1Handler))))
		// PutBucketLifecycle
		bucket.Methods(http.MethodPut).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("putbucketlifecycle", cmd.HTTPTraceAll(api.PutBucketLifecycleHandler)))).Queries("lifecycle", "")
		// PutBucketReplicationConfig
		bucket.Methods(http.MethodPut).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("putbucketreplicationconfiguration", cmd.HTTPTraceAll(api.PutBucketReplicationConfigHandler)))).Queries("replication", "")
		// GetObjectRetention

		// PutBucketEncryption
		bucket.Methods(http.MethodPut).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("putbucketencryption", cmd.HTTPTraceAll(api.PutBucketEncryptionHandler)))).Queries("encryption", "")

		// PutBucketPolicy
		bucket.Methods(http.MethodPut).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("putbucketpolicy", cmd.HTTPTraceAll(api.PutBucketPolicyHandler)))).Queries("policy", "")

		// PutBucketObjectLockConfig
		bucket.Methods(http.MethodPut).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("putbucketobjectlockconfig", cmd.HTTPTraceAll(api.PutBucketObjectLockConfigHandler)))).Queries("object-lock", "")
		// PutBucketTaggingHandler
		bucket.Methods(http.MethodPut).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("putbuckettagging", cmd.HTTPTraceAll(api.PutBucketTaggingHandler)))).Queries("tagging", "")
		// PutBucketVersioning
		bucket.Methods(http.MethodPut).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("putbucketversioning", cmd.HTTPTraceAll(api.PutBucketVersioningHandler)))).Queries("versioning", "")
		// PutBucketNotification
		bucket.Methods(http.MethodPut).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("putbucketnotification", cmd.HTTPTraceAll(api.PutBucketNotificationHandler)))).Queries("notification", "")
		// PutBucket
		bucket.Methods(http.MethodPut).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("putbucket", cmd.HTTPTraceAll(api.PutBucketHandler))))
		// HeadBucket
		bucket.Methods(http.MethodHead).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("headbucket", cmd.HTTPTraceAll(api.HeadBucketHandler))))
		// PostPolicy
		bucket.Methods(http.MethodPost).HeadersRegexp(xhttp.ContentType, "multipart/form-data*").Handler(
			limit(cmd.MaxClients(cmd.CollectAPIStats("postpolicybucket", cmd.HTTPTraceHdrs(api.PostPolicyBucketHandler)))))
		// DeleteMultipleObjects
		bucket.Methods(http.MethodPost).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("deletemultipleobjects", cmd.HTTPTraceAll(api.DeleteMultipleObjectsHandler)))).Queries("delete", "")
		// DeleteBucketPolicy
		bucket.Methods(http.MethodDelete).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("deletebucketpolicy", cmd.HTTPTraceAll(api.DeleteBucketPolicyHandler)))).Queries("policy", "")
		// DeleteBucketReplication
		bucket.Methods(http.MethodDelete).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("deletebucketreplicationconfiguration", cmd.HTTPTraceAll(api.DeleteBucketReplicationConfigHandler)))).Queries("replication", "")
		// DeleteBucketLifecycle
		bucket.Methods(http.MethodDelete).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("deletebucketlifecycle", cmd.HTTPTraceAll(api.DeleteBucketLifecycleHandler)))).Queries("lifecycle", "")
		// DeleteBucketEncryption
		bucket.Methods(http.MethodDelete).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("deletebucketencryption", cmd.HTTPTraceAll(api.DeleteBucketEncryptionHandler)))).Queries("encryption", "")
		// DeleteBucket
		bucket.Methods(http.MethodDelete).HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("deletebucket", cmd.HTTPTraceAll(api.DeleteBucketHandler))))
		// PostRestoreObject
		bucket.Methods(http.MethodPost).Path("/{object:.+}").HandlerFunc(
			cmd.MaxClients(cmd.CollectAPIStats("restoreobject", cmd.HTTPTraceAll(api.PostRestoreObjectHandler)))).Queries("restore", "")
	}

	// Root operation

	// ListenNotification
	apiRouter.Methods(http.MethodGet).Path(cmd.SlashSeparator).HandlerFunc(
		cmd.CollectAPIStats("listennotification", cmd.HTTPTraceAll(api.ListenNotificationHandler))).Queries("events", "{events:.*}")

	// ListBucketsWithAttribution (similar to ListBuckets)
	apiRouter.Methods(http.MethodGet).Path(cmd.SlashSeparator).HandlerFunc(
		cmd.MaxClients(cmd.CollectAPIStats("listbuckets", cmd.HTTPTraceAll(newListBucketsWithAttributionHandler(layer))))).Queries("attribution", "")

	// ListBuckets
	apiRouter.Methods(http.MethodGet).Path(cmd.SlashSeparator).HandlerFunc(
		cmd.MaxClients(cmd.CollectAPIStats("listbuckets", cmd.HTTPTraceAll(api.ListBucketsHandler))))

	// S3 browser with signature v4 adds '//' for ListBuckets request, so rather
	// than failing with UnknownAPIRequest we simply handle it for now.
	apiRouter.Methods(http.MethodGet).Path(cmd.SlashSeparator + cmd.SlashSeparator).HandlerFunc(
		cmd.MaxClients(cmd.CollectAPIStats("listbuckets", cmd.HTTPTraceAll(api.ListBucketsHandler))))

	// If none of the routes match add default error handler routes
	apiRouter.NotFoundHandler = cmd.CollectAPIStats("notfound", cmd.HTTPTraceAll(cmd.ErrorResponseHandler))
	apiRouter.MethodNotAllowedHandler = cmd.CollectAPIStats("methodnotallowed", cmd.HTTPTraceAll(cmd.MethodNotAllowedHandler("S3")))
}

// This file was derived from an Apache 2 licensed codebase.  The original is included below:

/*
 * MinIO Cloud Storage, (C) 2016-2020 MinIO, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// // registerAPIRouter - registers S3 compatible APIs.
// func registerAPIRouter(router *mux.Router) {
// 	// Initialize API.
// 	api := objectAPIHandlers{
// 		ObjectAPI: newObjectLayerFn,
// 		CacheAPI:  newCachedObjectLayerFn,
// 	}

// 	// API Router
// 	apiRouter := router.PathPrefix(SlashSeparator).Subrouter()

// 	var routers []*mux.Router
// 	for _, domainName := range globalDomainNames {
// 		if IsKubernetes() {
// 			routers = append(routers, apiRouter.MatcherFunc(func(r *http.Request, match *mux.RouteMatch) bool {
// 				host, _, err := net.SplitHostPort(getHost(r))
// 				if err != nil {
// 					host = r.Host
// 				}
// 				// Make sure to skip matching minio.<domain>` this is
// 				// specifically meant for operator/k8s deployment
// 				// The reason we need to skip this is for a special
// 				// usecase where we need to make sure that
// 				// minio.<namespace>.svc.<cluster_domain> is ignored
// 				// by the bucketDNS style to ensure that path style
// 				// is available and honored at this domain.
// 				//
// 				// All other `<bucket>.<namespace>.svc.<cluster_domain>`
// 				// makes sure that buckets are routed through this matcher
// 				// to match for `<bucket>`
// 				return host != minioReservedBucket+"."+domainName
// 			}).Host("{bucket:.+}."+domainName).Subrouter())
// 		} else {
// 			routers = append(routers, apiRouter.Host("{bucket:.+}."+domainName).Subrouter())
// 		}
// 	}
// 	routers = append(routers, apiRouter.PathPrefix("/{bucket}").Subrouter())

// 	for _, bucket := range routers {
// 		// Object operations
// 		// HeadObject
// 		bucket.Methods(http.MethodHead).Path("/{object:.+}").HandlerFunc(
// 			maxClients(collectAPIStats("headobject", httpTraceAll(api.HeadObjectHandler))))
// 		// CopyObjectPart
// 		bucket.Methods(http.MethodPut).Path("/{object:.+}").
// 			HeadersRegexp(xhttp.AmzCopySource, ".*?(\\/|%2F).*?").
// 			HandlerFunc(maxClients(collectAPIStats("copyobjectpart", httpTraceAll(api.CopyObjectPartHandler)))).
// 			Queries("partNumber", "{partNumber:[0-9]+}", "uploadId", "{uploadId:.*}")
// 		// PutObjectPart
// 		bucket.Methods(http.MethodPut).Path("/{object:.+}").HandlerFunc(
// 			maxClients(collectAPIStats("putobjectpart", httpTraceHdrs(api.PutObjectPartHandler)))).Queries("partNumber", "{partNumber:[0-9]+}", "uploadId", "{uploadId:.*}")
// 		// ListObjectParts
// 		bucket.Methods(http.MethodGet).Path("/{object:.+}").HandlerFunc(
// 			maxClients(collectAPIStats("listobjectparts", httpTraceAll(api.ListObjectPartsHandler)))).Queries("uploadId", "{uploadId:.*}")
// 		// CompleteMultipartUpload
// 		bucket.Methods(http.MethodPost).Path("/{object:.+}").HandlerFunc(
// 			maxClients(collectAPIStats("completemutipartupload", httpTraceAll(api.CompleteMultipartUploadHandler)))).Queries("uploadId", "{uploadId:.*}")
// 		// NewMultipartUpload
// 		bucket.Methods(http.MethodPost).Path("/{object:.+}").HandlerFunc(
// 			maxClients(collectAPIStats("newmultipartupload", httpTraceAll(api.NewMultipartUploadHandler)))).Queries("uploads", "")
// 		// AbortMultipartUpload
// 		bucket.Methods(http.MethodDelete).Path("/{object:.+}").HandlerFunc(
// 			maxClients(collectAPIStats("abortmultipartupload", httpTraceAll(api.AbortMultipartUploadHandler)))).Queries("uploadId", "{uploadId:.*}")
// 		// GetObjectACL - this is a dummy call.
// 		bucket.Methods(http.MethodGet).Path("/{object:.+}").HandlerFunc(
// 			maxClients(collectAPIStats("getobjectacl", httpTraceHdrs(api.GetObjectACLHandler)))).Queries("acl", "")
// 		// PutObjectACL - this is a dummy call.
// 		bucket.Methods(http.MethodPut).Path("/{object:.+}").HandlerFunc(
// 			maxClients(collectAPIStats("putobjectacl", httpTraceHdrs(api.PutObjectACLHandler)))).Queries("acl", "")
// 		// GetObjectTagging
// 		bucket.Methods(http.MethodGet).Path("/{object:.+}").HandlerFunc(
// 			maxClients(collectAPIStats("getobjecttagging", httpTraceHdrs(api.GetObjectTaggingHandler)))).Queries("tagging", "")
// 		// PutObjectTagging
// 		bucket.Methods(http.MethodPut).Path("/{object:.+}").HandlerFunc(
// 			maxClients(collectAPIStats("putobjecttagging", httpTraceHdrs(api.PutObjectTaggingHandler)))).Queries("tagging", "")
// 		// DeleteObjectTagging
// 		bucket.Methods(http.MethodDelete).Path("/{object:.+}").HandlerFunc(
// 			maxClients(collectAPIStats("deleteobjecttagging", httpTraceHdrs(api.DeleteObjectTaggingHandler)))).Queries("tagging", "")
// 		// SelectObjectContent
// 		bucket.Methods(http.MethodPost).Path("/{object:.+}").HandlerFunc(
// 			maxClients(collectAPIStats("selectobjectcontent", httpTraceHdrs(api.SelectObjectContentHandler)))).Queries("select", "").Queries("select-type", "2")
// 		// GetObjectRetention
// 		bucket.Methods(http.MethodGet).Path("/{object:.+}").HandlerFunc(
// 			maxClients(collectAPIStats("getobjectretention", httpTraceAll(api.GetObjectRetentionHandler)))).Queries("retention", "")
// 		// GetObjectLegalHold
// 		bucket.Methods(http.MethodGet).Path("/{object:.+}").HandlerFunc(
// 			maxClients(collectAPIStats("getobjectlegalhold", httpTraceAll(api.GetObjectLegalHoldHandler)))).Queries("legal-hold", "")
// 		// GetObject
// 		bucket.Methods(http.MethodGet).Path("/{object:.+}").HandlerFunc(
// 			maxClients(collectAPIStats("getobject", httpTraceHdrs(api.GetObjectHandler))))
// 		// CopyObject
// 		bucket.Methods(http.MethodPut).Path("/{object:.+}").HeadersRegexp(xhttp.AmzCopySource, ".*?(\\/|%2F).*?").
// 			HandlerFunc(maxClients(collectAPIStats("copyobject", httpTraceAll(api.CopyObjectHandler))))
// 		// PutObjectRetention
// 		bucket.Methods(http.MethodPut).Path("/{object:.+}").HandlerFunc(
// 			maxClients(collectAPIStats("putobjectretention", httpTraceAll(api.PutObjectRetentionHandler)))).Queries("retention", "")
// 		// PutObjectLegalHold
// 		bucket.Methods(http.MethodPut).Path("/{object:.+}").HandlerFunc(
// 			maxClients(collectAPIStats("putobjectlegalhold", httpTraceAll(api.PutObjectLegalHoldHandler)))).Queries("legal-hold", "")

// 		// PutObject
// 		bucket.Methods(http.MethodPut).Path("/{object:.+}").HandlerFunc(
// 			maxClients(collectAPIStats("putobject", httpTraceHdrs(api.PutObjectHandler))))
// 		// DeleteObject
// 		bucket.Methods(http.MethodDelete).Path("/{object:.+}").HandlerFunc(
// 			maxClients(collectAPIStats("deleteobject", httpTraceAll(api.DeleteObjectHandler))))

// 		/// Bucket operations
// 		// GetBucketLocation
// 		bucket.Methods(http.MethodGet).HandlerFunc(
// 			maxClients(collectAPIStats("getbucketlocation", httpTraceAll(api.GetBucketLocationHandler)))).Queries("location", "")
// 		// GetBucketPolicy
// 		bucket.Methods(http.MethodGet).HandlerFunc(
// 			maxClients(collectAPIStats("getbucketpolicy", httpTraceAll(api.GetBucketPolicyHandler)))).Queries("policy", "")
// 		// GetBucketLifecycle
// 		bucket.Methods(http.MethodGet).HandlerFunc(
// 			maxClients(collectAPIStats("getbucketlifecycle", httpTraceAll(api.GetBucketLifecycleHandler)))).Queries("lifecycle", "")
// 		// GetBucketEncryption
// 		bucket.Methods(http.MethodGet).HandlerFunc(
// 			maxClients(collectAPIStats("getbucketencryption", httpTraceAll(api.GetBucketEncryptionHandler)))).Queries("encryption", "")
// 		// GetBucketObjectLockConfig
// 		bucket.Methods(http.MethodGet).HandlerFunc(
// 			maxClients(collectAPIStats("getbucketobjectlockconfiguration", httpTraceAll(api.GetBucketObjectLockConfigHandler)))).Queries("object-lock", "")
// 		// GetBucketReplicationConfig
// 		bucket.Methods(http.MethodGet).HandlerFunc(
// 			maxClients(collectAPIStats("getbucketreplicationconfiguration", httpTraceAll(api.GetBucketReplicationConfigHandler)))).Queries("replication", "")

// 		// GetBucketVersioning
// 		bucket.Methods(http.MethodGet).HandlerFunc(
// 			maxClients(collectAPIStats("getbucketversioning", httpTraceAll(api.GetBucketVersioningHandler)))).Queries("versioning", "")
// 		// GetBucketNotification
// 		bucket.Methods(http.MethodGet).HandlerFunc(
// 			maxClients(collectAPIStats("getbucketnotification", httpTraceAll(api.GetBucketNotificationHandler)))).Queries("notification", "")
// 		// ListenNotification
// 		bucket.Methods(http.MethodGet).HandlerFunc(collectAPIStats("listennotification", httpTraceAll(api.ListenNotificationHandler))).Queries("events", "{events:.*}")

// 		// Dummy Bucket Calls
// 		// GetBucketACL -- this is a dummy call.
// 		bucket.Methods(http.MethodGet).HandlerFunc(
// 			maxClients(collectAPIStats("getbucketacl", httpTraceAll(api.GetBucketACLHandler)))).Queries("acl", "")
// 		// PutBucketACL -- this is a dummy call.
// 		bucket.Methods(http.MethodPut).HandlerFunc(
// 			maxClients(collectAPIStats("putbucketacl", httpTraceAll(api.PutBucketACLHandler)))).Queries("acl", "")
// 		// GetBucketCors - this is a dummy call.
// 		bucket.Methods(http.MethodGet).HandlerFunc(
// 			maxClients(collectAPIStats("getbucketcors", httpTraceAll(api.GetBucketCorsHandler)))).Queries("cors", "")
// 		// GetBucketWebsiteHandler - this is a dummy call.
// 		bucket.Methods(http.MethodGet).HandlerFunc(
// 			maxClients(collectAPIStats("getbucketwebsite", httpTraceAll(api.GetBucketWebsiteHandler)))).Queries("website", "")
// 		// GetBucketAccelerateHandler - this is a dummy call.
// 		bucket.Methods(http.MethodGet).HandlerFunc(
// 			maxClients(collectAPIStats("getbucketaccelerate", httpTraceAll(api.GetBucketAccelerateHandler)))).Queries("accelerate", "")
// 		// GetBucketRequestPaymentHandler - this is a dummy call.
// 		bucket.Methods(http.MethodGet).HandlerFunc(
// 			maxClients(collectAPIStats("getbucketrequestpayment", httpTraceAll(api.GetBucketRequestPaymentHandler)))).Queries("requestPayment", "")
// 		// GetBucketLoggingHandler - this is a dummy call.
// 		bucket.Methods(http.MethodGet).HandlerFunc(
// 			maxClients(collectAPIStats("getbucketlogging", httpTraceAll(api.GetBucketLoggingHandler)))).Queries("logging", "")
// 		// GetBucketLifecycleHandler - this is a dummy call.
// 		bucket.Methods(http.MethodGet).HandlerFunc(
// 			maxClients(collectAPIStats("getbucketlifecycle", httpTraceAll(api.GetBucketLifecycleHandler)))).Queries("lifecycle", "")
// 		// GetBucketTaggingHandler
// 		bucket.Methods(http.MethodGet).HandlerFunc(
// 			maxClients(collectAPIStats("getbuckettagging", httpTraceAll(api.GetBucketTaggingHandler)))).Queries("tagging", "")
// 		//DeleteBucketWebsiteHandler
// 		bucket.Methods(http.MethodDelete).HandlerFunc(
// 			maxClients(collectAPIStats("deletebucketwebsite", httpTraceAll(api.DeleteBucketWebsiteHandler)))).Queries("website", "")
// 		// DeleteBucketTaggingHandler
// 		bucket.Methods(http.MethodDelete).HandlerFunc(
// 			maxClients(collectAPIStats("deletebuckettagging", httpTraceAll(api.DeleteBucketTaggingHandler)))).Queries("tagging", "")

// 		// ListMultipartUploads
// 		bucket.Methods(http.MethodGet).HandlerFunc(
// 			maxClients(collectAPIStats("listmultipartuploads", httpTraceAll(api.ListMultipartUploadsHandler)))).Queries("uploads", "")
// 		// ListObjectsV2M
// 		bucket.Methods(http.MethodGet).HandlerFunc(
// 			maxClients(collectAPIStats("listobjectsv2M", httpTraceAll(api.ListObjectsV2MHandler)))).Queries("list-type", "2", "metadata", "true")
// 		// ListObjectsV2
// 		bucket.Methods(http.MethodGet).HandlerFunc(
// 			maxClients(collectAPIStats("listobjectsv2", httpTraceAll(api.ListObjectsV2Handler)))).Queries("list-type", "2")
// 		// ListObjectVersions
// 		bucket.Methods(http.MethodGet).HandlerFunc(
// 			maxClients(collectAPIStats("listobjectversions", httpTraceAll(api.ListObjectVersionsHandler)))).Queries("versions", "")
// 		// ListObjectsV1 (Legacy)
// 		bucket.Methods(http.MethodGet).HandlerFunc(
// 			maxClients(collectAPIStats("listobjectsv1", httpTraceAll(api.ListObjectsV1Handler))))
// 		// PutBucketLifecycle
// 		bucket.Methods(http.MethodPut).HandlerFunc(
// 			maxClients(collectAPIStats("putbucketlifecycle", httpTraceAll(api.PutBucketLifecycleHandler)))).Queries("lifecycle", "")
// 		// PutBucketReplicationConfig
// 		bucket.Methods(http.MethodPut).HandlerFunc(
// 			maxClients(collectAPIStats("putbucketreplicationconfiguration", httpTraceAll(api.PutBucketReplicationConfigHandler)))).Queries("replication", "")
// 		// GetObjectRetention

// 		// PutBucketEncryption
// 		bucket.Methods(http.MethodPut).HandlerFunc(
// 			maxClients(collectAPIStats("putbucketencryption", httpTraceAll(api.PutBucketEncryptionHandler)))).Queries("encryption", "")

// 		// PutBucketPolicy
// 		bucket.Methods(http.MethodPut).HandlerFunc(
// 			maxClients(collectAPIStats("putbucketpolicy", httpTraceAll(api.PutBucketPolicyHandler)))).Queries("policy", "")

// 		// PutBucketObjectLockConfig
// 		bucket.Methods(http.MethodPut).HandlerFunc(
// 			maxClients(collectAPIStats("putbucketobjectlockconfig", httpTraceAll(api.PutBucketObjectLockConfigHandler)))).Queries("object-lock", "")
// 		// PutBucketTaggingHandler
// 		bucket.Methods(http.MethodPut).HandlerFunc(
// 			maxClients(collectAPIStats("putbuckettagging", httpTraceAll(api.PutBucketTaggingHandler)))).Queries("tagging", "")
// 		// PutBucketVersioning
// 		bucket.Methods(http.MethodPut).HandlerFunc(
// 			maxClients(collectAPIStats("putbucketversioning", httpTraceAll(api.PutBucketVersioningHandler)))).Queries("versioning", "")
// 		// PutBucketNotification
// 		bucket.Methods(http.MethodPut).HandlerFunc(
// 			maxClients(collectAPIStats("putbucketnotification", httpTraceAll(api.PutBucketNotificationHandler)))).Queries("notification", "")
// 		// PutBucket
// 		bucket.Methods(http.MethodPut).HandlerFunc(
// 			maxClients(collectAPIStats("putbucket", httpTraceAll(api.PutBucketHandler))))
// 		// HeadBucket
// 		bucket.Methods(http.MethodHead).HandlerFunc(
// 			maxClients(collectAPIStats("headbucket", httpTraceAll(api.HeadBucketHandler))))
// 		// PostPolicy
// 		bucket.Methods(http.MethodPost).HeadersRegexp(xhttp.ContentType, "multipart/form-data*").HandlerFunc(
// 			maxClients(collectAPIStats("postpolicybucket", httpTraceHdrs(api.PostPolicyBucketHandler))))
// 		// DeleteMultipleObjects
// 		bucket.Methods(http.MethodPost).HandlerFunc(
// 			maxClients(collectAPIStats("deletemultipleobjects", httpTraceAll(api.DeleteMultipleObjectsHandler)))).Queries("delete", "")
// 		// DeleteBucketPolicy
// 		bucket.Methods(http.MethodDelete).HandlerFunc(
// 			maxClients(collectAPIStats("deletebucketpolicy", httpTraceAll(api.DeleteBucketPolicyHandler)))).Queries("policy", "")
// 		// DeleteBucketReplication
// 		bucket.Methods(http.MethodDelete).HandlerFunc(
// 			maxClients(collectAPIStats("deletebucketreplicationconfiguration", httpTraceAll(api.DeleteBucketReplicationConfigHandler)))).Queries("replication", "")
// 		// DeleteBucketLifecycle
// 		bucket.Methods(http.MethodDelete).HandlerFunc(
// 			maxClients(collectAPIStats("deletebucketlifecycle", httpTraceAll(api.DeleteBucketLifecycleHandler)))).Queries("lifecycle", "")
// 		// DeleteBucketEncryption
// 		bucket.Methods(http.MethodDelete).HandlerFunc(
// 			maxClients(collectAPIStats("deletebucketencryption", httpTraceAll(api.DeleteBucketEncryptionHandler)))).Queries("encryption", "")
// 		// DeleteBucket
// 		bucket.Methods(http.MethodDelete).HandlerFunc(
// 			maxClients(collectAPIStats("deletebucket", httpTraceAll(api.DeleteBucketHandler))))
// 		// PostRestoreObject
// 		bucket.Methods(http.MethodPost).Path("/{object:.+}").HandlerFunc(
// 			maxClients(collectAPIStats("restoreobject", httpTraceAll(api.PostRestoreObjectHandler)))).Queries("restore", "")
// 	}

// 	/// Root operation

// 	// ListenNotification
// 	apiRouter.Methods(http.MethodGet).Path(SlashSeparator).HandlerFunc(
// 		collectAPIStats("listennotification", httpTraceAll(api.ListenNotificationHandler))).Queries("events", "{events:.*}")

// 	// ListBuckets
// 	apiRouter.Methods(http.MethodGet).Path(SlashSeparator).HandlerFunc(
// 		maxClients(collectAPIStats("listbuckets", httpTraceAll(api.ListBucketsHandler))))

// 	// S3 browser with signature v4 adds '//' for ListBuckets request, so rather
// 	// than failing with UnknownAPIRequest we simply handle it for now.
// 	apiRouter.Methods(http.MethodGet).Path(SlashSeparator + SlashSeparator).HandlerFunc(
// 		maxClients(collectAPIStats("listbuckets", httpTraceAll(api.ListBucketsHandler))))

// 	// If none of the routes match add default error handler routes
// 	apiRouter.NotFoundHandler = collectAPIStats("notfound", httpTraceAll(errorResponseHandler))
// 	apiRouter.MethodNotAllowedHandler = collectAPIStats("methodnotallowed", httpTraceAll(methodNotAllowedHandler("S3")))

// }
