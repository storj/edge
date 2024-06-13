// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package accesslogs

import (
	"errors"

	"github.com/zeebo/errs"
)

var (
	// Error is the error class for this package.
	Error = errs.Class("accesslogs")
	// ErrClosed means that the peer has already been closed.
	ErrClosed = errors.New("closed")
	// ErrTooLarge means that the provided payload is too large.
	ErrTooLarge = errors.New("entry too large")
	// ErrQueueLimit means that the upload queue limit has been reached.
	ErrQueueLimit = errors.New("upload queue limit reached")
)
