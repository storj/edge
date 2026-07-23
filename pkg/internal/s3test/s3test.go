// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

// Package s3test provides helpers to discover credentials for S3-related tests.
// It mirrors storj.io/edge/pkg/internal/gcstest.
package s3test

import (
	"context"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/zeebo/errs"

	"storj.io/common/testrand"
)

// PathLengthLimit is a conservative maximum object-key length used by tests.
const PathLengthLimit = 1024

var (
	// Error is the error class for this package.
	Error = errs.Class("s3test")
	// ErrCredentialsNotFound is returned when the bucket/region haven't been
	// found by FindCredentials.
	ErrCredentialsNotFound = errs.Class("credentials not found")
)

// Config holds the settings needed to reach an S3 bucket in tests.
type Config struct {
	Bucket          string
	Region          string
	AccessKeyID     string
	SecretAccessKey string
	Endpoint        string
}

// FindCredentials tries to find the S3 bucket/region (and optional
// credentials/endpoint) for S3-related tests, returning ErrCredentialsNotFound
// otherwise.
func FindCredentials() (Config, error) {
	bucket := os.Getenv("STORJ_TEST_S3_BUCKET")
	region := os.Getenv("STORJ_TEST_S3_REGION")

	if bucket == "" || region == "" {
		return Config{}, ErrCredentialsNotFound.New("")
	}

	return Config{
		Bucket:          bucket,
		Region:          region,
		AccessKeyID:     os.Getenv("STORJ_TEST_S3_ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("STORJ_TEST_S3_SECRET_ACCESS_KEY"),
		Endpoint:        os.Getenv("STORJ_TEST_S3_ENDPOINT"),
	}, nil
}

// Client builds an *s3.Client from the config. Static credentials are used when
// set; otherwise the AWS default credential chain applies. A non-empty endpoint
// switches on path-style addressing (for S3-compatible endpoints).
func (c Config) Client(ctx context.Context) (*s3.Client, error) {
	opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(c.Region)}
	if c.AccessKeyID != "" {
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(c.AccessKeyID, c.SecretAccessKey, ""),
		))
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		if c.Endpoint != "" {
			o.BaseEndpoint = aws.String(c.Endpoint)
			o.UsePathStyle = true
		}
	}), nil
}

// RandPathUTF8 returns a random path that does not exceed maxLen bytes and is a
// valid UTF-8 string.
func RandPathUTF8(maxLen int) string {
	var b strings.Builder
	for _, r := range strings.ToValidUTF8(testrand.Path(), "�") {
		if b.Len()+4 >= maxLen { // calculate conservatively
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}
