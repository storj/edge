// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetermineBucketAndObjectKey(t *testing.T) {
	for idx, test := range []struct {
		name          string
		root, urlPath string
		bucket, key   string
	}{
		{
			name:    "simple",
			root:    "bucket/prefix/",
			urlPath: "/images/pic.jpg",
			bucket:  "bucket",
			key:     "prefix/images/pic.jpg",
		},
		{
			name:    "standalone bucket",
			root:    "bucket",
			urlPath: "/images/pic.jpg",
			bucket:  "bucket",
			key:     "images/pic.jpg",
		},
		{
			name:    "bucket with slash",
			root:    "bucket/",
			urlPath: "/images/pic.jpg",
			bucket:  "bucket",
			key:     "images/pic.jpg",
		},
		{
			name:    "bucket with slash as prefix",
			root:    "bucket//",
			urlPath: "/images/pic.jpg",
			bucket:  "bucket",
			key:     "/images/pic.jpg",
		},
		{
			name:    "bucket with two slashes as prefix but no trailing slash",
			root:    "bucket//prefix",
			urlPath: "/images/pic.jpg",
			bucket:  "bucket",
			key:     "/prefix/images/pic.jpg",
		},
		{
			name:    "bucket with two slashes after prefix",
			root:    "bucket/prefix//",
			urlPath: "/images/pic.jpg",
			bucket:  "bucket",
			key:     "prefix//images/pic.jpg",
		},
		{
			name:    "prefix with no slash",
			root:    "bucket/prefix",
			urlPath: "/images/pic.jpg",
			bucket:  "bucket",
			key:     "prefix/images/pic.jpg",
		},
		{
			name:    "url with two slashes",
			root:    "bucket/prefix/",
			urlPath: "//images/pic.jpg",
			bucket:  "bucket",
			key:     "prefix//images/pic.jpg",
		},
	} {
		actualBucket, actualKey := determineBucketAndObjectKey(test.root, test.urlPath)
		assert.Equal(t, actualBucket, test.bucket, fmt.Sprintf("%d: %s", idx, test.name))
		assert.Equal(t, actualKey, test.key, fmt.Sprintf("%d: %s", idx, test.name))
	}
}
