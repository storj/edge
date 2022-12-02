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
		ctx := cmd.NewContext(r, w, "ListBucketsWithAttribution")

		defer logger.AuditLog(ctx, w, r, nil)

		if _, _, s3Error := cmd.CheckRequestAuthTypeCredential(ctx, r, policy.ListAllMyBucketsAction, "", ""); s3Error != cmd.ErrNone {
			cmd.WriteErrorResponse(ctx, w, cmd.GetAPIError(s3Error), r.URL, false)
			return
		}

		buckets, err := layer.ListBucketsWithAttribution(ctx)
		if err != nil {
			cmd.WriteErrorResponse(ctx, w, cmd.ToAPIError(ctx, err), r.URL, false)
			return
		}

		response := generateListBucketsWithAttributionResponse(buckets)

		cmd.WriteSuccessResponseXML(w, cmd.EncodeResponse(response))
	}
}
