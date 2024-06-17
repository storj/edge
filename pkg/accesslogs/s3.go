// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.
package accesslogs

import (
	"fmt"
	"time"

	"storj.io/common/memory"
)

// S3AccessLogEntry represents all the fields that are needed for producing S3 access log entry and implements the Entry interface.
type S3AccessLogEntry struct {
	logline string

	BucketOwner        string        // example: 79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be, should be project UUID of the project for us
	Bucket             string        // example: DOC-EXAMPLE-BUCKET1
	Timestamp          time.Time     // example: 06/Feb/2019:00:00:38 +0000
	RemoteIp           string        // example: 192.0.2.3
	Requester          string        // example: 79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be, should be hardcoded '' for iuse
	RequestId          string        // example: 3E57427F3EXAMPLE
	Operation          string        // example: REST.GET.VERSIONING
	Key                string        // example: /photos/2019/08/puppy.jpg
	RequestURI         string        // example: GET /DOC-EXAMPLE-BUCKET1/photos/2019/08/puppy.jpg?x-foo=bar HTTP/1.1, it's OK if we include credentials
	HttpStatus         int64         // example: 200
	ErrorCode          string        // example: NoSuchBucket
	BytesSent          int64         // example: 2662992
	ObjectSize         int64         // example: 3462992
	TotalTime          time.Duration // example: 70
	TurnAroundTime     time.Duration // example: 10, this can be fetched from Metrics Middleware probably?
	Referer            string        // example: http://www.example.com/webservices
	UserAgent          string        // example: curl/7.15.1
	VersionId          string        // example: 3HL4kqtJvjVBH40Nrjfkd, check both request and response headers in search for versionId
	HostId             string        // example: SHA for gateway's hostname, e.g. for dp-prod-edge-ch1-2
	SignatureVersion   string        // example: SigV4, todo: most of the requests are SigV4 anyways, but let's get the actual value
	CipherSuite        string        // example: ECDHE-RSA-AES128-GCM-SHA256 r.TLS.CipherSuite or - if it doesn't exist, 	// if r.TLS != nil
	AuthenticationType string        // example: AuthHeader, same as signature version. Get it from credentials parser.
	HostHeader         string        // example: s3.us-west-2.amazonaws.com
	TlsVersion         string        // example: TLSv1.2, get it from r.TLS
	AccessPointARN     string        // example: arn:aws:s3:us-east-1:123456789012:accesspoint/example-AP, we don't use ARNs so let's '-' it
	AclRequired        string        // example: Yes
}

// Size returns the size of the Entry in bytes, so it meets the Entry interface.
func (a S3AccessLogEntry) Size() memory.Size {
	return memory.Size(len(a.logline))
}

// String returns the formatted S3 access log entry (as per https://docs.aws.amazon.com/AmazonS3/latest/userguide/LogFormat.html), so it meets the Entry interface.
func (a S3AccessLogEntry) String() string {
	return fmt.Sprintf("%s %s [%s] %s %s %s %s %s \"%s\" %d %s %d %d %d %d \"%s\" \"%s\" %s %s %s %s %s %s %s %s %s\n",
		a.BucketOwner, a.Bucket, S3formattedstrftime(a.Timestamp), a.RemoteIp, a.Requester, a.RequestId, a.Operation, a.Key, a.RequestURI, a.HttpStatus, a.ErrorCode, a.BytesSent, a.ObjectSize,
		a.TotalTime/time.Millisecond, a.TurnAroundTime/time.Millisecond, a.Referer, a.UserAgent, a.VersionId, a.HostId, a.SignatureVersion, a.CipherSuite, a.AuthenticationType, a.HostHeader,
		a.TlsVersion, a.AccessPointARN, a.AclRequired)
}

// S3formattedstrftime formats the time in the way S3 expects it: [%d/%b/%Y:%H:%M:%S %z].
func S3formattedstrftime(t time.Time) string {
	t = t.UTC()
	return t.Format("02/Jan/2006:15:04:05 -0700")
}
