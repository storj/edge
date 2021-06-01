// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package miniogw

import (
	"context"
	"testing"

	"github.com/storj/minio/cmd/logger"
	"github.com/stretchr/testify/require"
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

func TestAccessKeyHash(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"test123", "ecd71870d1963316a97e3ac3408c9835ad8cf0f3c1bc703527c30265534f75ae"},
		{"", ""},
	}
	for i, tc := range tests {
		var reqInfo logger.ReqInfo
		reqInfo.AccessKey = tc.input
		output := getAccessKeyHash(&reqInfo)
		require.Equal(t, tc.expected, output, i)
	}
}
