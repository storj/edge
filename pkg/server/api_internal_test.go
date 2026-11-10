// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/edge/pkg/server/gwlog"
	"storj.io/gateway/api"
)

func TestSlowDownRetryAfter(t *testing.T) {
	// t.Setenv restores the variable after the test, which os.Unsetenv doesn't.
	t.Setenv("STORJ_MINIO_RETRY_AFTER", "")
	require.NoError(t, os.Unsetenv("STORJ_MINIO_RETRY_AFTER"))
	retryAfter, err := slowDownRetryAfter()
	require.NoError(t, err)
	require.Equal(t, 12*time.Second, retryAfter)

	t.Setenv("STORJ_MINIO_RETRY_AFTER", "30")
	retryAfter, err = slowDownRetryAfter()
	require.NoError(t, err)
	require.Equal(t, 30*time.Second, retryAfter)

	for _, value := range []string{"", "1.5", "Wed, 21 Oct 2015 07:28:00 GMT"} {
		t.Setenv("STORJ_MINIO_RETRY_AFTER", value)
		_, err = slowDownRetryAfter()
		require.Error(t, err, value)
	}
}

// TestAPIFillsInLog checks that a request that fails before reaching the object layer is logged
// with its operation, bucket, object and error code.
func TestAPIFillsInLog(t *testing.T) {
	router := mux.NewRouter()
	require.NoError(t, registerAPI(zaptest.NewLogger(t), router, nil, nil, nil, 1))

	log := gwlog.New()
	req := httptest.NewRequestWithContext(log.WithContext(t.Context()), http.MethodGet, "/bucket/key", nil)
	now := time.Now().UTC()
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/"+now.Format("20060102")+"/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature="+strings.Repeat("0", 64))
	req.Header.Set("X-Amz-Date", now.Format("20060102T150405Z"))
	req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Equal(t, "GetObject", log.API)
	require.Equal(t, "bucket", log.BucketName)
	require.Equal(t, "key", log.ObjectName)
	require.Equal(t, rec.Header().Get("X-Amz-Request-Id"), log.RequestID)
	require.Equal(t, "InvalidAccessKeyId", log.TagValue(api.ErrorCodeTag))
}
