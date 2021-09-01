// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package server

// Config determines how server listens for requests.
type Config struct {
	Address string `help:"Address to serve gateway on" default:"127.0.0.1:7777"`
	Dir     string `help:"Minio generic server config path" default:"$CONFDIR/minio"`
}

// S3CompatibilityConfig gathers parameters that control how strict the S3
// compatibility is.
type S3CompatibilityConfig struct {
	IncludeCustomMetadataListing bool `help:"include custom metadata in S3's ListObjects, ListObjectsV2 and ListMultipartUploads responses" default:"true"`
	MaxKeysLimit                 int  `help:"MaxKeys parameter limit for S3's ListObjects and ListObjectsV2 responses" default:"1000"`
	DisableCopyObject            bool `help:"return HTTP 501 not implemented for CopyObject calls" devDefault:"false" releaseDefault:"true"`
	MinPartSize                  int  `help:"Minimum parts size for mulitpart uploads" default:"5242880"` // 5mB
}
