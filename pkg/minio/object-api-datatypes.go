// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package minio

import "time"

// BucketWithAttributionInfo represents a bucket with attribution metadata.
type BucketWithAttributionInfo struct {
	Name        string
	Attribution string
	Created     time.Time
}
