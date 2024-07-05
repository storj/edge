// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.
package accesslogs

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestS3AccessLogEntry(t *testing.T) {
	testTime, err := time.Parse(time.RFC3339, "2024-12-21T13:45:10Z")
	require.NoError(t, err)

	objectSize := 0

	o := S3AccessLogEntryOptions{
		BucketOwner:        "bucketOwner",
		Bucket:             "bucketName",
		Time:               testTime,
		RemoteIP:           "8.8.8.8",
		Requester:          "publicProjectId",
		RequestID:          "requestId",
		Operation:          "REST.GET.VERSIONING",
		Key:                "/test/puppy.jpg",
		RequestURI:         "GET /DOC-EXAMPLE-BUCKET1/photos/2019/08/puppy.jpg?x-foo=bar HTTP/1.1",
		HTTPStatus:         200,
		ErrorCode:          "NoSuchBucket",
		BytesSent:          1234,
		ObjectSize:         &objectSize,
		TotalTime:          123 * time.Millisecond,
		TurnAroundTime:     456 * time.Millisecond,
		Referer:            "https://example.com",
		UserAgent:          "curl 8.8",
		VersionID:          "versionId",
		HostID:             "hostId",
		SignatureVersion:   "SigV4",
		CipherSuite:        "TLS_AES_128_GCM_SHA256",
		AuthenticationType: "AuthHeader",
		HostHeader:         "gateway.storjshare.io",
		TLSVersion:         "TLSv1.2",
	}

	e := NewS3AccessLogEntry(o)

	require.True(t, e.Size() > 0)

	want := "bucketOwner bucketName [21/Dec/2024:13:45:10 +0000] 8.8.8.8 publicProjectId requestId REST.GET.VERSIONING /test/puppy.jpg \"GET /DOC-EXAMPLE-BUCKET1/photos/2019/08/puppy.jpg?x-foo=bar HTTP/1.1\" 200 NoSuchBucket 1234 0 123 456 \"https://example.com\" \"curl 8.8\" versionId hostId SigV4 TLS_AES_128_GCM_SHA256 AuthHeader gateway.storjshare.io TLSv1.2 - -"
	require.Equal(t, want, e.String())
}

var result string

func BenchmarkS3AccessLogEntryToString(b *testing.B) {
	testTime, err := time.Parse(time.RFC3339, "2024-12-21T13:45:10Z")
	require.NoError(b, err)

	o := S3AccessLogEntryOptions{
		BucketOwner:        "bucketOwner",
		Bucket:             "bucketName",
		Time:               testTime,
		RemoteIP:           "8.8.8.8",
		Requester:          "publicProjectId",
		RequestID:          "requestId",
		Operation:          "REST.GET.VERSIONING",
		Key:                "/test/puppy.jpg",
		RequestURI:         "GET /DOC-EXAMPLE-BUCKET1/photos/2019/08/puppy.jpg?x-foo=bar HTTP/1.1",
		HTTPStatus:         200,
		ErrorCode:          "NoSuchBucket",
		BytesSent:          1234,
		TotalTime:          123 * time.Millisecond,
		TurnAroundTime:     456 * time.Millisecond,
		Referer:            "https://example.com",
		UserAgent:          "curl 8.8",
		VersionID:          "versionId",
		HostID:             "hostId",
		SignatureVersion:   "SigV4",
		CipherSuite:        "TLS_AES_128_GCM_SHA256",
		AuthenticationType: "AuthHeader",
		HostHeader:         "gateway.storjshare.io",
		TLSVersion:         "TLSv1.2",
	}

	b.ResetTimer()

	var r string
	for i := 0; i < b.N; i++ {
		r = NewS3AccessLogEntry(o).String()
	}
	result = r
}
