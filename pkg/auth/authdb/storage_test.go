// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package authdb

import (
	"testing"

	"github.com/stretchr/testify/require"

	"storj.io/common/testrand"
)

func TestKeyHash(t *testing.T) {
	data := testrand.RandAlphaNumeric(32)

	var kh KeyHash
	require.NoError(t, kh.SetBytes(data))
	require.Equal(t, data, kh.Bytes())

	var kh2 KeyHash
	encoded := kh.ToHex()
	require.Len(t, encoded, KeyHashSizeEncoded)
	require.Error(t, kh2.FromHex(encoded[1:]))
	require.Equal(t, KeyHash{}, kh2)
	require.Error(t, kh2.FromHex("g"+encoded[1:]))
	require.Equal(t, KeyHash{}, kh2)
	require.NoError(t, kh2.FromHex(encoded))
	require.Equal(t, kh, kh2)
}
