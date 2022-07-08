// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package gw

import (
	"context"
	"errors"
	"net/http"
	"testing"

	miniogo "github.com/minio/minio-go/v7"
	"github.com/stretchr/testify/require"

	"storj.io/gateway-mt/pkg/server/gwlog"
	"storj.io/gateway/miniogw"
	minio "storj.io/minio/cmd"
	"storj.io/minio/cmd/logger"
	"storj.io/uplink"
)

func TestGetUserAgent(t *testing.T) {
	// ignore bad user agents
	reqInfo := logger.ReqInfo{UserAgent: "Test/1.0 S3 Browser 9.5.5 https://s3browser.com"}
	ctx := logger.SetReqInfo(context.Background(), &reqInfo)
	results := getUserAgent(ctx)
	require.Equal(t, "Gateway-MT/v0.0.0", results)
	// preserve good user agents
	reqInfo = logger.ReqInfo{UserAgent: "Test/1.0 S3-Browser/9.5.5 (https://s3browser.com)"}
	ctx = logger.SetReqInfo(context.Background(), &reqInfo)
	results = getUserAgent(ctx)
	require.Equal(t, "Test/1.0 S3-Browser/9.5.5 (https://s3browser.com) Gateway-MT/v0.0.0", results)
}

func TestMinioError(t *testing.T) {
	tests := []struct {
		input    error
		expected bool
	}{
		{errors.New("some error"), false},
		{uplink.ErrBucketNameInvalid, false},
		{miniogo.ErrorResponse{Message: "oops"}, true},
		{miniogw.ErrBandwidthLimitExceeded, true},
		{miniogw.ErrSlowDown, true},
		{minio.BucketNotEmpty{}, true},
	}
	for i, tc := range tests {
		require.Equal(t, tc.expected, minioError(tc.input), i)
	}
}

func TestLogUnexpectedErrorsOnly(t *testing.T) {
	tests := []struct {
		input    error
		expected string
	}{
		{context.Canceled, ""},
		{minio.BucketNotEmpty{}, ""},
		{miniogo.ErrorResponse{Message: "oops"}, ""},
		{miniogw.ErrBandwidthLimitExceeded, ""},
		{miniogw.ErrSlowDown, ""},
		{uplink.ErrBucketNameInvalid, uplink.ErrBucketNameInvalid.Error()},
		{errors.New("unexpected error"), "unexpected error"},
	}
	for i, tc := range tests {
		log := gwlog.New()
		ctx := log.WithContext(context.Background())
		require.Error(t, (&MultiTenancyLayer{minio.GatewayUnsupported{}, nil, nil, uplink.Config{}, false}).log(ctx, tc.input))
		require.Equal(t, tc.expected, log.TagValue("error"), i)
	}
}

func TestLogAllErrors(t *testing.T) {
	tests := []struct {
		input    error
		expected string
	}{
		{context.Canceled, context.Canceled.Error()},
		{minio.BucketNotEmpty{}, minio.BucketNotEmpty{}.Error()},
		{uplink.ErrBucketNameInvalid, uplink.ErrBucketNameInvalid.Error()},
		{errors.New("unexpected error"), "unexpected error"},
	}
	for i, tc := range tests {
		log := gwlog.New()
		ctx := log.WithContext(context.Background())
		require.Error(t, (&MultiTenancyLayer{minio.GatewayUnsupported{}, nil, nil, uplink.Config{}, true}).log(ctx, tc.input))
		require.Equal(t, tc.expected, log.TagValue("error"), i)
	}
}

func TestInvalidAccessGrant(t *testing.T) {
	layer := &MultiTenancyLayer{minio.GatewayUnsupported{}, nil, nil, uplink.Config{}, true}
	_, err := layer.ListBuckets(context.Background())
	require.Error(t, err)
	require.IsType(t, miniogo.ErrorResponse{}, err)
	require.Equal(t, http.StatusUnauthorized, miniogo.ToErrorResponse(err).StatusCode)
}
