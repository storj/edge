// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package minio

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestObjectPathToUser(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "config/iam/users/someUser/identity.json",
			expected: "someUser",
		},
		{
			input:    "invalid",
			expected: "",
		},
		{
			input:    ".",
			expected: "",
		},
		{
			input:    "/",
			expected: "",
		},
		{
			input:    "//",
			expected: "",
		},
	}
	for i, tc := range tests {
		require.Equal(t, tc.expected, objectPathToUser(tc.input), i)
	}
}
