// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package sharedlink

import (
	"net/url"
	"strings"

	"github.com/zeebo/errs"

	"storj.io/gateway-mt/pkg/server/middleware"
)

// Error is a class of sharedlink errors.
var Error = errs.Class("sharedlink")

// Link is a parsed link from Linksharing, or S3 presigned.
type Link struct {
	AccessKey string
}

// Parse parses a raw URL and returns a Link. It supports Linksharing links
// with /s or /raw path prefix, or S3 presigned V2 or V4 links.
//
// Currently it only parses the access key.
func Parse(rawURL string) (*Link, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	var accessKey string
	path := u.EscapedPath()

	switch {
	// linksharing URL, e.g. "https://link.storjshare.io/s/<access-key>/<bucket>/<object-key>"
	case strings.HasPrefix(path, "/s") || strings.HasPrefix(path, "/raw"):
		parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 3)
		if len(parts) < 2 || len(parts[1]) == 0 {
			return nil, Error.New("access key not found in url %q", rawURL)
		}
		accessKey = parts[1]
	// S3 v2 presigned URL, e.g. "https://gateway.storjshare.io/<bucket>/<object-key>?AWSAccessKeyId=<access-key>..."
	case u.Query().Get("AWSAccessKeyId") != "":
		accessKey = u.Query().Get("AWSAccessKeyId")
	// S3 v4 presigned URL, e.g. "https://gateway.storjshare.io/<bucket>/<object-key>?X-Amz-Credential=<access-key>/20230524/us-east-1/s3/aws4_request..."
	case u.Query().Get("X-Amz-Credential") != "":
		credential, err := middleware.ParseV4Credential(u.Query().Get("X-Amz-Credential"))
		if err != nil {
			return nil, err
		}
		accessKey = credential.AccessKeyID
	default:
		return nil, Error.New("unknown url %q", rawURL)
	}

	return &Link{
		AccessKey: accessKey,
	}, nil
}
