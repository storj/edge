// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package errdata

import (
	"errors"

	"github.com/zeebo/errs"
)

type errWrap struct {
	error
	key, val interface{}
}

type errWithValue interface {
	Value(key interface{}) interface{}
}

var _ errWithValue = errWrap{}
var _ errs.Namer = errWrap{}

func (e errWrap) Unwrap() error { return e.error }

func (e errWrap) Name() (string, bool) {
	for i := e.error; i != nil; i = errors.Unwrap(i) {
		if u, ok := i.(errs.Namer); ok { //nolint: errorlint // custom unwrap loop.
			if name, ok := u.Name(); ok {
				return name, true
			}
		}
	}
	return "", false
}

func (e errWrap) Value(key interface{}) interface{} {
	if e.key == key {
		return e.val
	}
	return Value(e.error, key)
}

// Value returns the most recent annotation by key on this error.
func Value(err error, key interface{}) interface{} {
	for e := err; e != nil; e = errors.Unwrap(e) {
		if u, ok := e.(errWithValue); ok { //nolint: errorlint // custom unwrap loop.
			return u.Value(key)
		}
	}
	return nil
}

// Annotate returns a new error annotated with the provided key and value.
// If err is nil, does nothing.
func Annotate(err error, key, val interface{}) error {
	if err == nil {
		return nil
	}
	return errWrap{error: err, key: key, val: val}
}
