// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"bytes"
	"io"

	"github.com/zeebo/errs"
)

// bodyCache wraps a ReadCloser to allow rereading a single time after reset.
type bodyCache struct {
	stream         io.ReadCloser // the original stream, less the cache
	bufferedStream io.Reader     // the buffered stream
	bytes          *bytes.Buffer // the body cache
	hasReset       bool          // true if we've reset the stream
}

// newBodyCache returns a ReadCloser which buffers bytes until reset.
func newBodyCache(stream io.ReadCloser) *bodyCache {
	var bytes bytes.Buffer
	return &bodyCache{
		stream:         stream,
		bufferedStream: io.TeeReader(stream, &bytes),
		bytes:          &bytes,
	}
}

// Read implements the io.Reader interface.
func (r *bodyCache) Read(b []byte) (n int, err error) {
	if r.hasReset {
		n, _ := r.bytes.Read(b)
		m, err := r.stream.Read(b[n:])
		if err != nil && n != 0 {
			err = nil
		}
		return n + m, err
	}
	return r.bufferedStream.Read(b)
}

// Close closes the underlying stream.
func (r *bodyCache) Close() error {
	r.bytes.Reset()
	return r.stream.Close()
}

// Reset seeks to beginning of buffer and stops further buffering.
func (r *bodyCache) Reset() error {
	if r.hasReset {
		return errs.New("already reset")
	}
	r.hasReset = true
	return nil
}
