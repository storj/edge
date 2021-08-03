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
		{"test123", "ecd71870d1963316a97e3ac3408c9835ad8cf0f3c1bc703527c30265534f75ae"},
		{"", ""},
	}
	for i, tc := range tests {
		log := New()
		log.AccessKey = tc.input
		require.Equal(t, tc.expected, log.AccessKeyHash(), i)
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
