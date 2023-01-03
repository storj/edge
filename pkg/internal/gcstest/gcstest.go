// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package gcstest

import (
	"os"
	"strings"

	"github.com/zeebo/errs"

	"storj.io/common/testrand"
)

var (
	// Error is the error class for this package.
	Error = errs.Class("gcstest")
	// ErrCredentialsNotFound is returned when the JSON key/bucket name hasn't
	// been found by FindCredentials.
	ErrCredentialsNotFound = Error.New("credentials not found")
)

// FindCredentials tries to find the JSON key and bucket name for GCS-related
// tests and returns ErrCredentialsNotFound otherwise.
func FindCredentials() (jsonKey []byte, bucket string, err error) {
	pathToJsonKey := os.Getenv("STORJ_TEST_GCSTEST_PATH_TO_JSON_KEY")
	bucket = os.Getenv("STORJ_TEST_GCSTEST_BUCKET")

	if pathToJsonKey == "" || bucket == "" {
		return nil, "", ErrCredentialsNotFound
	}

	jsonKey, err = os.ReadFile(pathToJsonKey)
	return jsonKey, bucket, Error.Wrap(err)
}

// RandPathUTF8 returns a random path that, when UTF-8-formatted, does not
// exceed maxLen bytes.
func RandPathUTF8(maxLen int) string {
	p := strings.ToValidUTF8(testrand.Path(), "\ufffd")
	for len(p) > maxLen {
		p = p[:len(p)-1]
	}
	return p
}
