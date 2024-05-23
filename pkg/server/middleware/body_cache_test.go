// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewBodyCache(t *testing.T) {

	orig := io.NopCloser(bytes.NewBuffer([]byte("This is a test")))
	bc := newBodyCache(orig)

	this := make([]byte, 4)
	n, err := bc.Read(this)
	require.NoError(t, err)
	require.Equal(t, []byte("This"), this)
	require.Equal(t, 4, n)
	require.NoError(t, err)

	is := make([]byte, 4)
	n, err = bc.Read(is)
	require.Equal(t, []byte(" is "), is)
	require.Equal(t, 4, n)
	require.NoError(t, err)

	require.NoError(t, bc.Reset())
	thisIsA := make([]byte, 10)
	n, err = bc.Read(thisIsA)
	require.NoError(t, err)
	require.Equal(t, []byte("This is a "), thisIsA)
	require.Equal(t, 10, n)

	test := make([]byte, 64)
	n, err = bc.Read(test)
	require.NoError(t, err)
	require.Equal(t, []byte("test"), test[:n])
	require.Equal(t, 4, n)

	// Empty Buffer
	orig = io.NopCloser(bytes.NewBuffer([]byte("")))
	bc = newBodyCache(orig)
	empty := make([]byte, 64)
	n, err = bc.Read(empty)
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, 0, n)
	require.NoError(t, bc.Reset())
	n, err = bc.Read(empty)
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, 0, n)

	// Read until EOF, reset
	orig = io.NopCloser(bytes.NewBuffer([]byte("12")))
	bc = newBodyCache(orig)
	one := make([]byte, 1)
	n, err = bc.Read(one)
	require.NoError(t, err)
	require.Equal(t, []byte("1"), one)
	require.Equal(t, 1, n)
	n, err = bc.Read(one)
	require.NoError(t, err)
	require.Equal(t, []byte("2"), one)
	require.Equal(t, 1, n)
	n, err = bc.Read(one)
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, 0, n)

	require.NoError(t, bc.Reset())
	n, err = bc.Read(one)
	require.NoError(t, err)
	require.Equal(t, []byte("1"), one)
	require.Equal(t, 1, n)
	n, err = bc.Read(one)
	require.NoError(t, err)
	require.Equal(t, []byte("2"), one)
	require.Equal(t, 1, n)
	n, err = bc.Read(one)
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, 0, n)

	// Read half buffer and reset
	orig = io.NopCloser(bytes.NewBuffer([]byte("12")))
	bc = newBodyCache(orig)
	one = make([]byte, 1)
	n, err = bc.Read(one)
	require.NoError(t, err)
	require.Equal(t, []byte("1"), one)
	require.Equal(t, 1, n)

	require.NoError(t, bc.Reset())
	two := make([]byte, 2)
	n, err = bc.Read(two)
	require.NoError(t, err)
	require.Equal(t, []byte("12"), two)
	require.Equal(t, 2, n)
	n, err = bc.Read(one)
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, 0, n)

	// Read whole buffer then reset
	orig = io.NopCloser(bytes.NewBuffer([]byte("12")))
	bc = newBodyCache(orig)
	ten := make([]byte, 10)
	n, err = bc.Read(ten)
	require.NoError(t, err)
	require.Equal(t, []byte("12"), ten[:2])
	require.Equal(t, 2, n)
	n, err = bc.Read(one)
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, 0, n)

	require.NoError(t, bc.Reset())
	ten = make([]byte, 10)
	n, err = bc.Read(ten)
	require.NoError(t, err)
	require.Equal(t, []byte("12"), ten[:2])
	require.Equal(t, 2, n)
	n, err = bc.Read(one)
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, 0, n)

	// Double reset
	require.Error(t, bc.Reset())
}
