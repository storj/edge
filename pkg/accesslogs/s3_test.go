// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.
package accesslogs

import (
	"testing"
	"time"
)

// TestHelloName calls greetings.Hello with a name, checking
// for a valid return value.
func TestS3AccessLogEntryToString(t *testing.T) {
	const layout = "2006-01-02T15:04:05"

	// Calling Parse() method with its parameters
	randomTime, _ := time.Parse(layout, "2024-12-21T13:45:10")
	ale := S3AccessLogEntry{
		BucketOwner:        "bucketOwner",
		Bucket:             "bucketName",
		Timestamp:          randomTime,
		RemoteIp:           "8.8.8.8",
		Requester:          "publicProjectId",
		RequestId:          "requestId",
		Operation:          "REST.GET.VERSIONING",
		Key:                "/test/puppy.jpg",
		RequestURI:         "GET /DOC-EXAMPLE-BUCKET1/photos/2019/08/puppy.jpg?x-foo=bar HTTP/1.1",
		HttpStatus:         200,
		ErrorCode:          "NoSuchBucket",
		BytesSent:          1234,
		ObjectSize:         0,
		TotalTime:          123 * time.Millisecond,
		TurnAroundTime:     0,
		Referer:            "https://example.com",
		UserAgent:          "curl 8.8",
		VersionId:          "versionId",
		HostId:             "hostId",
		SignatureVersion:   "SigV4",
		CipherSuite:        "TLS_AES_128_GCM_SHA256",
		AuthenticationType: "AuthHeader",
		HostHeader:         "gateway.storjshare.io",
		TlsVersion:         "TLSv1.2",
		AccessPointARN:     "-",
		AclRequired:        "-",
	}

	msg := ale.String()
	want := "bucketOwner bucketName [21/Dec/2024:13:45:10 +0000] 8.8.8.8 publicProjectId requestId REST.GET.VERSIONING /test/puppy.jpg \"GET /DOC-EXAMPLE-BUCKET1/photos/2019/08/puppy.jpg?x-foo=bar HTTP/1.1\" 200 NoSuchBucket 1234 0 123 0 \"https://example.com\" \"curl 8.8\" versionId hostId SigV4 TLS_AES_128_GCM_SHA256 AuthHeader gateway.storjshare.io TLSv1.2 - -\n"
	if msg != want {
		t.Fatalf("Unexpected S3-formatting: %q, want: %q", msg, want)
	}
}

var resultLogline string

func BenchmarkS3AccessLogEntryToString(b *testing.B) {
	const layout = "2006-01-02T15:04:05"
	randomTime, _ := time.Parse(layout, "2024-12-21T13:45:10")
	ale := S3AccessLogEntry{
		BucketOwner:        "bucketOwner",
		Bucket:             "bucketName",
		Timestamp:          randomTime,
		RemoteIp:           "8.8.8.8",
		Requester:          "publicProjectId",
		RequestId:          "requestId",
		Operation:          "REST.GET.VERSIONING",
		Key:                "/test/puppy.jpg",
		RequestURI:         "GET /DOC-EXAMPLE-BUCKET1/photos/2019/08/puppy.jpg?x-foo=bar HTTP/1.1",
		HttpStatus:         200,
		ErrorCode:          "NoSuchBucket",
		BytesSent:          1234,
		ObjectSize:         0,
		TotalTime:          123 * time.Millisecond,
		TurnAroundTime:     0,
		Referer:            "https://example.com",
		UserAgent:          "curl 8.8",
		VersionId:          "versionId",
		HostId:             "hostId",
		SignatureVersion:   "SigV4",
		CipherSuite:        "TLS_AES_128_GCM_SHA256",
		AuthenticationType: "AuthHeader",
		HostHeader:         "gateway.storjshare.io",
		TlsVersion:         "TLSv1.2",
		AccessPointARN:     "-",
		AclRequired:        "-",
	}

	b.ResetTimer()

	var logline string
	for i := 0; i < b.N; i++ {
		logline = ale.String()
	}
	// Store the result to a package level variable, so the compiler cannot eliminate the Benchmark itself? https://dave.cheney.net/2013/06/30/how-to-write-benchmarks-in-go
	resultLogline = logline
}
