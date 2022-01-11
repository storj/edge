// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package gwlog

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAccessKeyHash(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"test123", ""},
		{"jwtx7ngonjgwh6icz5omblkyfhxa", "32bf8c1f116fc383bbdc7462c8f0f575b8f1d25088a39ebbb68aad1e308812a7"},
		{"", ""},
	}
	for i, tc := range tests {
		log := New()
		log.AccessKey = tc.input
		require.Equal(t, tc.expected, log.EncryptionKeyHash(), i)
	}
}

func TestGetReqInfo(t *testing.T) {
	log, ok := FromContext(context.Background())
	require.Nil(t, log)
	require.False(t, ok)

	log = New()
	log.RequestID = "123"
	ctx := log.WithContext(context.Background())
	log2, ok := FromContext(ctx)
	require.True(t, ok)
	require.Equal(t, "123", log2.RequestID)
	require.Equal(t, log, log2)
}

func TestTagValue(t *testing.T) {
	log := New()
	log.SetTags("error", "some error")
	require.Equal(t, "some error", log.TagValue("error"))
	require.Equal(t, "", log.TagValue("nonexistentkey"))
}
