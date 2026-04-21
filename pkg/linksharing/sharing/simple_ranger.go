// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"context"
	"io"

	"github.com/zeebo/errs"

	"storj.io/common/ranger"
)

// UnsupportedRange is returned if a SimpleRanger is used in a way unsupported by a Reader.
var UnsupportedRange = errs.Class("unsupported range")

type simpleRanger struct {
	rc   *readCloserOnce
	size int64
}

// SimpleRanger implements a Ranger using a ReadCloser, throwing an error for unsupported Range reads.
func SimpleRanger(readCloser io.ReadCloser, size int64) ranger.Ranger {
	return &simpleRanger{rc: &readCloserOnce{ReadCloser: readCloser}, size: size}
}

// Size returns object size.
func (ranger *simpleRanger) Size() int64 {
	return ranger.size
}

// Range returns object read/close interface.
func (ranger *simpleRanger) Range(ctx context.Context, offset, length int64) (_ io.ReadCloser, err error) {
	defer mon.Task()(&ctx)(&err)
	if offset != 0 {
		return nil, UnsupportedRange.New("non-zero offset")
	}
	if length < 0 {
		return nil, UnsupportedRange.New("negative length")
	}
	if offset+length > ranger.size {
		return nil, UnsupportedRange.New("buffer runoff")
	}
	return ranger.rc, nil
}

func (ranger *simpleRanger) Read(p []byte) (n int, err error) {
	if ranger.rc.ReadCloser == nil {
		return 0, nil
	}
	return ranger.rc.Read(p)
}

func (ranger *simpleRanger) Close() error {
	if ranger.rc.ReadCloser == nil {
		return nil
	}
	return ranger.rc.Close()
}
