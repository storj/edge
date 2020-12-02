// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package auth

import (
	"testing"

	"github.com/stretchr/testify/require"

	"storj.io/common/encryption"
	"storj.io/common/storj"
)

func TestBase32(t *testing.T) {
	oldKey, err := NewEncryptionKey()
	require.NoError(t, err)
	require.NotEqual(t, oldKey, EncryptionKey{})
	encoded := oldKey.ToBase32()
	require.Len(t, encoded, eKeySizeEncoded)
	var newKey EncryptionKey
	err = newKey.FromBase32(encoded)
	require.NoError(t, err)
	require.Equal(t, newKey, oldKey)
	require.NotEqual(t, newKey, EncryptionKey{})
}

func TestBase32Fail(t *testing.T) {
	key, err := NewEncryptionKey()
	require.NoError(t, err)
	encoded := key.ToBase32()
	require.Len(t, encoded, eKeySizeEncoded)
	require.Error(t, key.FromBase32(encoded[1:]))
	require.Error(t, key.FromBase32(encoded[2:]))
	encoded = "a" + encoded[1:]
	require.Error(t, key.FromBase32(encoded))
}

func TestNonceIncrement(t *testing.T) {
	nonce := storj.Nonce{}
	_, err := encryption.Increment(&nonce, 1)
	require.NoError(t, err)
	require.Equal(t, storj.Nonce{1}, nonce)
}
