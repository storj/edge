// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"errors"
	"io"

	"github.com/zeebo/errs"
)

// BodyCache wraps a ReadCloser to allow seeking the first N bytes.
type BodyCache struct {
	stream        io.ReadCloser // the original stream, less the cache
	bytes         []byte        // the body cache
	hasReadStream bool          // true if we've consumed the stream beyond the cache
	i             int64         // current reading index
}

// NewBodyCache return a ReadCloser than can Seek the first bufferSize bytes.
func NewBodyCache(stream io.ReadCloser, bufferSize int64) (*BodyCache, error) {
	bytes, err := io.ReadAll(io.LimitReader(stream, bufferSize))
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return &BodyCache{bytes: bytes, stream: stream}, nil
}

// Read implements the io.Reader interface.
func (r *BodyCache) Read(b []byte) (n int, err error) {
	if r.i < int64(len(r.bytes)) {
		n = copy(b, r.bytes[r.i:])
		r.i += int64(n)
	}
	if n < len(b) {
		sn, err := r.stream.Read(b[n:])
		if sn > 0 {
			r.i += int64(sn)
			r.hasReadStream = true
		}
		return n + sn, err
	}
	return n, err
}

// Seek implements the io.Seeker interface.
func (r *BodyCache) Seek(offset int64, whence int) (int64, error) {
	if r.hasReadStream {
		return 0, errs.New("cannot reset after reading stream")
	}
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = r.i + offset
	case io.SeekEnd:
		return 0, errs.New("credReader.Seek: cannot SeekEnd")
	default:
		return 0, errs.New("credReader.Seek: invalid whence")
	}
	if abs < 0 {
		return 0, errs.New("credReader.Seek: negative position")
	}
	r.i = abs
	return abs, nil
}

// Close closes the underlying stream.
func (r *BodyCache) Close() error {
	r.bytes = []byte{}
	return r.stream.Close()
}
