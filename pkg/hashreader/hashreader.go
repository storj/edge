// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package hashreader

import (
	"hash"
	"io"
)

// Reader wraps an io.Reader calculating a hash of the underlying reads.
type Reader struct {
	r io.Reader
	h hash.Hash
}

// New returns a new Reader using the given hash implementation.
func New(r io.Reader, h hash.Hash) *Reader {
	return &Reader{
		r: r,
		h: h,
	}
}

// Read reads the underlying reader and writes the hash of it.
func (r *Reader) Read(b []byte) (n int, err error) {
	n, err = r.r.Read(b)
	if n > 0 {
		if _, err := r.h.Write(b[:n]); err != nil {
			return n, err
		}
	}
	return
}

// Sum returns the hash sum.
func (r *Reader) Sum() []byte {
	return r.h.Sum(nil)
}
