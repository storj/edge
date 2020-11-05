// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package auth

import "github.com/spacemonkeygo/monkit/v3"

var mon = monkit.Package()

const (
	// VersionAccessKeyID is the base58 version for encoding Access Key IDs.
	VersionAccessKeyID byte = 1

	// VersionSecretKey is the base58 version for encoding Secret Keys.
	VersionSecretKey byte = 2
)
