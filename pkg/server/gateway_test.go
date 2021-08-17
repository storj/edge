// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"context"
	"errors"
	"testing"

	minio "github.com/storj/minio/cmd"
	"github.com/storj/minio/cmd/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"storj.io/gateway-mt/pkg/server/gwlog"
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

func TestLogUnexpectedErrorsOnly(t *testing.T) {
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
		(&gateway{minio.GatewayUnsupported{}, uplink.Config{}, nil, S3CompatibilityConfig{}, false}).log(ctx, tc.input)
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
		(&gateway{minio.GatewayUnsupported{}, uplink.Config{}, nil, S3CompatibilityConfig{}, true}).log(ctx, tc.input)
		require.Equal(t, tc.expected, log.TagValue("error"), i)
	}
}

func TestLimitMaxKeys(t *testing.T) {
	g := gateway{
		compatibilityConfig: S3CompatibilityConfig{
			MaxKeysLimit: 1000,
		},
	}

	for i, tt := range [...]struct {
		maxKeys  int
		expected int
	}{
		{-10000, 999},
		{-4500, 999},
		{-1000, 999},
		{-999, 999},
		{-998, 999},
		{-500, 999},
		{-1, 999},
		{0, 999},
		{1, 1},
		{500, 500},
		{998, 998},
		{999, 999},
		{1000, 999},
		{4500, 999},
		{10000, 999},
	} {
		assert.Equal(t, tt.expected, g.limitMaxKeys(tt.maxKeys), i)
	}
}
