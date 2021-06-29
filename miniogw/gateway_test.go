// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package miniogw

import (
	"context"
	"errors"
	"testing"

	minio "github.com/storj/minio/cmd"
	"github.com/storj/minio/cmd/logger"
	"github.com/stretchr/testify/require"

	"storj.io/gateway-mt/pkg/gwlog"
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
		{minio.SlowDown{}, true},
		{minio.ProjectUsageLimit{}, true},
		{minio.BucketNotEmpty{}, true},
	}
	for i, tc := range tests {
		require.Equal(t, tc.expected, minioError(tc.input), i)
	}
}

func TestLogUnexpectedError(t *testing.T) {
	tests := []struct {
		input    error
		expected string
	}{
		{context.Canceled, ""},
		{minio.BucketNotEmpty{}, ""},
		{uplink.ErrBucketNameInvalid, uplink.ErrBucketNameInvalid.Error()},
		{errors.New("unexpected error"), "unexpected error"},
	}
	for i, tc := range tests {
		log := gwlog.New()
		ctx := log.WithContext(context.Background())
		(&gateway{minio.GatewayUnsupported{}, uplink.Config{}, nil}).log(ctx, tc.input)
		require.Equal(t, tc.expected, log.TagValue("error"), i)
	}
}
