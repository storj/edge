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
	bc, err := NewBodyCache(orig, 8)
	require.NoError(t, err)

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

	_, err = bc.Seek(-8, io.SeekCurrent)
	require.NoError(t, err)
	require.Equal(t, []byte("This"), this)
	require.Equal(t, 4, n)
	require.NoError(t, err)

	_, err = bc.Seek(0, io.SeekStart)
	require.NoError(t, err)
	thisIsA := make([]byte, 10)
	n, err = bc.Read(thisIsA)
	require.NoError(t, err)
	require.Equal(t, []byte("This is a "), thisIsA)
	require.Equal(t, 10, n)

	_, err = bc.Seek(0, io.SeekStart)
	require.Error(t, err)

	test := make([]byte, 64)
	n, err = bc.Read(test)
	require.NoError(t, err)
	require.Equal(t, []byte("test"), test[:n])
	require.Equal(t, 4, n)

}
