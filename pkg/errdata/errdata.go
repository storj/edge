// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package errdata

import (
	"errors"

	"github.com/zeebo/errs"
)

type errWrap struct {
	error
	key, val any
}

type errWithValue interface {
	Value(key any) any
}

var _ errWithValue = errWrap{}
var _ errs.Namer = errWrap{}

func (e errWrap) Unwrap() error { return e.error }

func (e errWrap) Name() (string, bool) {
	for i := e.error; i != nil; i = errors.Unwrap(i) {
		if u, ok := i.(errs.Namer); ok {
			if name, ok := u.Name(); ok {
				return name, true
			}
		}
	}
	return "", false
}

func (e errWrap) Value(key any) any {
	if e.key == key {
		return e.val
	}
	return Value(e.error, key)
}

// Value returns the most recent annotation by key on this error.
func Value(err error, key any) any {
	for e := err; e != nil; e = errors.Unwrap(e) {
		if u, ok := e.(errWithValue); ok {
			return u.Value(key)
		}
	}
	return nil
}

// Annotate returns a new error annotated with the provided key and value.
// If err is nil, does nothing.
func Annotate(err error, key, val any) error {
	if err == nil {
		return nil
	}
	return errWrap{error: err, key: key, val: val}
}
