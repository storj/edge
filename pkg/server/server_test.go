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

func TestRouting(t *testing.T) {
	ctx := testcontext.New(t)
	core, logs := observer.New(zapcore.DebugLevel)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	s := server.New(listener, zap.New(core))

	ctx.Go(func() error {
		return errs2.IgnoreCanceled(s.Run(ctx))
	})
	defer ctx.Check(s.Close)

	urlBase := "http://" + listener.Addr().String() + "/"
	bucket := urlBase + "bucket"
	object := bucket + "/key"

	testRoute(t, logs, "DeleteObjectTagging", object+"?tagging", http.MethodDelete, "")
	testRoute(t, logs, "GetObjectTagging", object+"?tagging", http.MethodGet, "")
	testRoute(t, logs, "PutObjectTagging", object+"?tagging", http.MethodPut, "")

	testRoute(t, logs, "CreateMultipartUpload", object+"?uploads", http.MethodPost, "")
	testRoute(t, logs, "AbortMultipartUpload", object+"?uploadId=UploadId", http.MethodDelete, "")
	testRoute(t, logs, "ListParts", object+"?uploadId=UploadId", http.MethodGet, "")
	testRoute(t, logs, "CompleteMultipartUpload", object+"?uploadId=UploadId", http.MethodPost, "")
	testRoute(t, logs, "UploadPartCopy", object+"?uploadId=UploadId&partNumber=PartNumber", http.MethodPut, "x-amz-copy-source")
	testRoute(t, logs, "UploadPart", object+"?uploadId=UploadId&partNumber=PartNumber", http.MethodPut, "")

	testRoute(t, logs, "GetObject", object, http.MethodGet, "")
	testRoute(t, logs, "CopyObject", object, http.MethodPut, "x-amz-copy-source")
	testRoute(t, logs, "PutObject", object, http.MethodPut, "")
	testRoute(t, logs, "DeleteObject", object, http.MethodDelete, "")
	testRoute(t, logs, "HeadObject", object, http.MethodHead, "")

	testRoute(t, logs, "DeleteBucketTagging", bucket+"?tagging", http.MethodDelete, "")
	testRoute(t, logs, "GetBucketTagging", bucket+"?tagging", http.MethodGet, "")
	testRoute(t, logs, "PutBucketTagging", bucket+"?tagging", http.MethodPut, "")

	testRoute(t, logs, "DeleteObjects", bucket+"?delete", http.MethodPost, "")
	testRoute(t, logs, "ListMultipartUploads", bucket+"?uploads", http.MethodGet, "")
	testRoute(t, logs, "ListObjectsV2", bucket+"?list-type=2", http.MethodGet, "")

	testRoute(t, logs, "ListObjects", bucket, http.MethodGet, "")
	testRoute(t, logs, "CreateBucket", bucket, http.MethodPut, "")
	testRoute(t, logs, "DeleteBucket", bucket, http.MethodDelete, "")
	testRoute(t, logs, "HeadBucket", bucket, http.MethodHead, "")

	testRoute(t, logs, "ListBuckets", urlBase, http.MethodGet, "")
}

func testRoute(t *testing.T, logs *observer.ObservedLogs, expectedLog, url, httpMethod, header string) {
	req, err := http.NewRequest(httpMethod, url, nil)
	require.NoError(t, err)
	if header != "" {
		req.Header.Set(header, "any value currently works for testing")
	}
	client := http.Client{Timeout: 5 * time.Second}
	response, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	assert.Equal(t, expectedLog, logs.TakeAll()[0].Message)
}
