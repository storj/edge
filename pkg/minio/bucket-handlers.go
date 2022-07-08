// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package minio

import (
	"net/http"

	"storj.io/gateway-mt/pkg/server/gw"
	"storj.io/minio/cmd"
	"storj.io/minio/cmd/logger"
	"storj.io/minio/pkg/bucket/policy"
)

// newListBucketsWithAttributionHandler implements GET operation, returning a
// list of all buckets with attribution owned by the authenticated/authorized
// sender of the request.
func newListBucketsWithAttributionHandler(layer *gw.MultiTenancyLayer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := newContext(r, w, "ListBucketsWithAttribution")

		defer logger.AuditLog(ctx, w, r, nil)

		if _, _, s3Error := checkRequestAuthTypeCredential(ctx, r, policy.ListAllMyBucketsAction, "", ""); s3Error != cmd.ErrNone {
			writeErrorResponse(ctx, w, GetAPIError(s3Error), r.URL, false)
			return
		}

		buckets, err := layer.ListBucketsWithAttribution(ctx)
		if err != nil {
			writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL, false)
			return
		}

		response := generateListBucketsWithAttributionResponse(buckets)

		writeSuccessResponseXML(w, encodeResponse(response))
	}
}
