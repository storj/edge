// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package server_test

import (
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"storj.io/common/errs2"
	"storj.io/common/testcontext"
	"storj.io/gateway-mt/pkg/server"
)

func TestRoutingPathStyle(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()
	core, logs := observer.New(zapcore.DebugLevel)
	listener, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	_, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	s := server.New(listener, zap.New(core), "localhost")

	ctx.Go(func() error {
		return errs2.IgnoreCanceled(s.Run(ctx))
	})
	defer ctx.Check(s.Close)

	urlBase := "http://localhost:" + port + "/"
	bucket := urlBase + "bucket"
	object := urlBase + "bucket/key"
	testRouting(t, logs, urlBase, bucket, object, false)
	testRoute(t, logs, "ListBuckets", urlBase, http.MethodGet, false, false)
}

func TestRoutingVirtualHostStyle(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()
	core, logs := observer.New(zapcore.DebugLevel)
	listener, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	_, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	s := server.New(listener, zap.New(core), "localhost")

	ctx.Go(func() error {
		return errs2.IgnoreCanceled(s.Run(ctx))
	})
	defer ctx.Check(s.Close)

	urlBase := "http://localhost:" + port + "/"
	bucket := urlBase
	object := urlBase + "key"
	testRouting(t, logs, urlBase, bucket, object, true)
}

func testRouting(t *testing.T, logs *observer.ObservedLogs, urlBase, bucket, object string, shouldFakeHost bool) {
	testRoute(t, logs, "DeleteObjectTagging", object+"?tagging", http.MethodDelete, false, shouldFakeHost)
	testRoute(t, logs, "GetObjectTagging", object+"?tagging", http.MethodGet, false, shouldFakeHost)
	testRoute(t, logs, "PutObjectTagging", object+"?tagging", http.MethodPut, false, shouldFakeHost)

	testRoute(t, logs, "CreateMultipartUpload", object+"?uploads", http.MethodPost, false, shouldFakeHost)
	testRoute(t, logs, "AbortMultipartUpload", object+"?uploadId=UploadId", http.MethodDelete, false, shouldFakeHost)
	testRoute(t, logs, "ListParts", object+"?uploadId=UploadId", http.MethodGet, false, shouldFakeHost)
	testRoute(t, logs, "CompleteMultipartUpload", object+"?uploadId=UploadId", http.MethodPost, false, shouldFakeHost)
	testRoute(t, logs, "UploadPartCopy", object+"?uploadId=UploadId&partNumber=PartNumber", http.MethodPut, true, shouldFakeHost)
	testRoute(t, logs, "UploadPart", object+"?uploadId=UploadId&partNumber=PartNumber", http.MethodPut, false, shouldFakeHost)

	testRoute(t, logs, "GetObject", object, http.MethodGet, false, shouldFakeHost)
	testRoute(t, logs, "CopyObject", object, http.MethodPut, true, shouldFakeHost)
	testRoute(t, logs, "PutObject", object, http.MethodPut, false, shouldFakeHost)
	testRoute(t, logs, "DeleteObject", object, http.MethodDelete, false, shouldFakeHost)
	testRoute(t, logs, "HeadObject", object, http.MethodHead, false, shouldFakeHost)

	testRoute(t, logs, "DeleteBucketTagging", bucket+"?tagging", http.MethodDelete, false, shouldFakeHost)
	testRoute(t, logs, "GetBucketTagging", bucket+"?tagging", http.MethodGet, false, shouldFakeHost)
	testRoute(t, logs, "PutBucketTagging", bucket+"?tagging", http.MethodPut, false, shouldFakeHost)

	testRoute(t, logs, "DeleteObjects", bucket+"?delete", http.MethodPost, false, shouldFakeHost)
	testRoute(t, logs, "ListMultipartUploads", bucket+"?uploads", http.MethodGet, false, shouldFakeHost)
	testRoute(t, logs, "ListObjectsV2", bucket+"?list-type=2", http.MethodGet, false, shouldFakeHost)

	testRoute(t, logs, "ListObjects", bucket, http.MethodGet, false, shouldFakeHost)
	testRoute(t, logs, "CreateBucket", bucket, http.MethodPut, false, shouldFakeHost)
	testRoute(t, logs, "DeleteBucket", bucket, http.MethodDelete, false, shouldFakeHost)
	testRoute(t, logs, "HeadBucket", bucket, http.MethodHead, false, shouldFakeHost)
}

func testRoute(t *testing.T, logs *observer.ObservedLogs, expectedLog, url, httpMethod string, addAmzCopyHeader, shouldFakeHost bool) {
	req, err := http.NewRequest(httpMethod, url, nil)
	require.NoError(t, err)
	if addAmzCopyHeader {
		req.Header.Set("x-amz-copy-source", "any value currently works for testing")
	}
	if shouldFakeHost {
		req.Header.Set("Host", "bucket.localhost")
		req.Host = "bucket.localhost"
	}
	client := http.Client{Timeout: 5 * time.Second}
	response, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	require.Equal(t, 1, len(logs.All()), expectedLog)
	assert.Equal(t, expectedLog, logs.TakeAll()[0].Message)
}
