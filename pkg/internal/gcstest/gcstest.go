// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package gcstest

import (
	"os"
	"strings"

	"github.com/zeebo/errs"

	"storj.io/common/testrand"
)

// PathLengthLimit is the maximum path length that GCS supports (in bytes when
// UTF-8-formatted).
const PathLengthLimit = 1024

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

// RandPathUTF8 returns a random path that does not exceed maxLen bytes and is a
// valid UTF-8 string.
func RandPathUTF8(maxLen int) string {
	var b strings.Builder
	for _, r := range strings.ToValidUTF8(testrand.Path(), "\ufffd") {
		if b.Len()+4 >= maxLen { // calculate conservatively
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}
