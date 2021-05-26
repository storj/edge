// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/storj/minio/cmd"
	"go.uber.org/zap"

	"storj.io/common/errs2"
	"storj.io/gateway-mt/pkg/minio"
)

var mon = monkit.Package()

// WriteError takes a Storj error and maps its to a Minio API Error, this enabling
// reuse of Minio's ability to write S3 XML error responses.
func WriteError(ctx context.Context, w http.ResponseWriter, err error, reqURL *url.URL) {
	apiError := mapToAPIErrorCode(ctx, err)

	minio.WriteErrorResponse(ctx, w, minio.GetAPIError(apiError), reqURL)
}

// mapToAPIErrorCode takes a Storj error and returns a Minio APIErrorCode.
func mapToAPIErrorCode(ctx context.Context, err error) cmd.APIErrorCode {
	if err == nil {
		return cmd.ErrNone
	}

	// most of the time context canceled is intentionally caused by the client
	// to keep log message clean, we will only log it on debug level
	if errs2.IsCanceled(err) {
		zap.L().Debug("gateway error:", zap.Error(err))
		return cmd.ErrClientDisconnected
	}

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return cmd.ErrOperationTimedOut
	}

	mon.Event("gmt_unmapped_error", monkit.NewSeriesTag("error", err.Error()))
	minioMapping := minio.ToAPIErrorCode(ctx, err)
	return minioMapping
}
