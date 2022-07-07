// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package minio

import (
	"context"
	"net/http"

	"storj.io/minio/cmd"
	"storj.io/minio/cmd/logger"
	"storj.io/minio/pkg/bucket/policy"
)

// listBucketsWithAttribution is a placeholder for the implementation of listing
// buckets with attribution.
//
// Currently, it always returns no buckets and a nil error.
func listBucketsWithAttribution(ctx context.Context) (buckets []BucketWithAttributionInfo, err error) {
	return nil, nil
}

// listBucketsWithAttributionHandler implements GET operation, returning a list
// of all buckets with attribution owned by the authenticated/authorized sender
// of the request.
func listBucketsWithAttributionHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "ListBucketsWithAttribution")

	defer logger.AuditLog(ctx, w, r, nil)

	if _, _, s3Error := checkRequestAuthTypeCredential(ctx, r, policy.ListAllMyBucketsAction, "", ""); s3Error != cmd.ErrNone {
		writeErrorResponse(ctx, w, GetAPIError(s3Error), r.URL, false)
		return
	}

	buckets, err := listBucketsWithAttribution(ctx)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL, false)
		return
	}

	response := generateListBucketsWithAttributionResponse(buckets)

	writeSuccessResponseXML(w, encodeResponse(response))
}
