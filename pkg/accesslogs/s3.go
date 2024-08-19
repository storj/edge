// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.
package accesslogs

import (
	"strconv"
	"strings"
	"time"

	"storj.io/common/memory"
)

// S3AccessLogEntryOptions represents all fields needed for producing
// S3-style server access log entry.
type S3AccessLogEntryOptions struct {
	BucketOwner        string        // example: 79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be
	Bucket             string        // example: DOC-EXAMPLE-BUCKET1
	Time               time.Time     // example: [06/Feb/2019:00:00:38 +0000]
	RemoteIP           string        // example: 192.0.2.3
	Requester          string        // example: 79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be
	RequestID          string        // example: 3E57427F33A59F07
	Operation          string        // example: REST.PUT.OBJECT
	Key                string        // example: /photos/2019/08/puppy.jpg
	RequestURI         string        // example: "GET /DOC-EXAMPLE-BUCKET1/photos/2019/08/puppy.jpg?x-foo=bar HTTP/1.1"
	HTTPStatus         int           // example: 200
	ErrorCode          string        // example: NoSuchBucket
	BytesSent          int64         // example: 2662992
	ObjectSize         *int64        // example: 3462992
	TotalTime          time.Duration // example: 70
	TurnAroundTime     time.Duration // example: 10
	Referer            string        // example: "http://www.example.com/webservices"
	UserAgent          string        // example: "curl/7.15.1"
	VersionID          string        // example: 3HL4kqtJvjVBH40Nrjfkd
	HostID             string        // example: s9lzHYrFp76ZVxRcpX9+5cjAnEH2ROuNkd2BHfIa6UkFVdtjf5mKR3/eTPFvsiP/XV/VLi31234=
	SignatureVersion   string        // example: SigV2
	CipherSuite        string        // example: ECDHE-RSA-AES128-GCM-SHA256
	AuthenticationType string        // example: AuthHeader
	HostHeader         string        // example: s3.us-west-2.amazonaws.com
	TLSVersion         string        // example: TLSv1.2
	AccessPointARN     string        // example: arn:aws:s3:us-east-1:123456789012:accesspoint/example-AP
	ACLRequired        string        // example: Yes
}

// S3AccessLogEntry represents the S3-style server access log entry.
type S3AccessLogEntry struct {
	b *strings.Builder
}

// NewS3AccessLogEntry creates new S3AccessLogEntry.
//
// It assumes that all relevant fields are already escaped.
func NewS3AccessLogEntry(o S3AccessLogEntryOptions) *S3AccessLogEntry {
	e := new(S3AccessLogEntry)
	e.b = new(strings.Builder)

	e.writeString(o.BucketOwner)
	e.writeString(o.Bucket)

	if !o.Time.IsZero() {
		e.b.WriteRune('[')
		e.b.WriteString(o.Time.UTC().Format("02/Jan/2006:15:04:05 -0700"))
		e.b.WriteRune(']')
	} else {
		e.b.WriteRune('-')
	}
	e.b.WriteRune(' ')

	e.writeString(o.RemoteIP)
	e.writeString(o.Requester)
	e.writeString(o.RequestID)
	e.writeString(o.Operation)
	e.writeString(o.Key)
	e.writeQuotedString(o.RequestURI)
	e.writeInt(o.HTTPStatus)
	e.writeString(o.ErrorCode)
	e.writeInt64(o.BytesSent)

	if o.ObjectSize != nil {
		e.b.WriteString(strconv.FormatInt(*o.ObjectSize, 10))
	} else {
		e.b.WriteRune('-')
	}
	e.b.WriteRune(' ')

	e.writeInt64(o.TotalTime.Milliseconds())
	e.writeInt64(o.TurnAroundTime.Milliseconds())
	e.writeQuotedString(o.Referer)
	e.writeQuotedString(o.UserAgent)
	e.writeString(o.VersionID)
	e.writeString(o.HostID)
	e.writeString(o.SignatureVersion)
	e.writeString(o.CipherSuite)
	e.writeString(o.AuthenticationType)
	e.writeString(o.HostHeader)
	e.writeString(o.TLSVersion)
	e.writeString(o.AccessPointARN)

	if o.ACLRequired != "" {
		e.b.WriteString(o.ACLRequired)
	} else {
		e.b.WriteRune('-')
	}

	return e
}

// Size returns the size of the entry.
func (e S3AccessLogEntry) Size() memory.Size {
	return memory.Size(e.b.Len())
}

// String returns the formatted entry (as per
// https://docs.aws.amazon.com/AmazonS3/latest/userguide/LogFormat.html).
func (e S3AccessLogEntry) String() string {
	return e.b.String()
}

func (e S3AccessLogEntry) writeString(s string) {
	if s != "" {
		e.b.WriteString(s)
	} else {
		e.b.WriteRune('-')
	}
	e.b.WriteRune(' ')
}

func (e S3AccessLogEntry) writeQuotedString(s string) {
	if s != "" {
		e.b.WriteRune('"')
		e.b.WriteString(s)
		e.b.WriteRune('"')
	} else {
		e.b.WriteRune('-')
	}
	e.b.WriteRune(' ')
}

func (e S3AccessLogEntry) writeInt(i int) {
	if i > 0 {
		e.b.WriteString(strconv.Itoa(i))
	} else {
		e.b.WriteRune('-')
	}
	e.b.WriteRune(' ')
}

func (e S3AccessLogEntry) writeInt64(i int64) {
	if i > 0 {
		e.b.WriteString(strconv.FormatInt(i, 10))
	} else {
		e.b.WriteRune('-')
	}
	e.b.WriteRune(' ')
}
