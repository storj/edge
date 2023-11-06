// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRawLinkURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   string
		want string
	}{
		{
			"http://link.storjshare.io/s/abc123/link/it%27s%20working%21.webp?wrap=1",
			"http://link.storjshare.io/raw/abc123/link/it%27s%20working%21.webp",
		},
		{
			"https://link.storjshare.io/s/abc123/hackervideo-bucket/demo%201%20shower%20thoughts.mp4",
			"https://link.storjshare.io/raw/abc123/hackervideo-bucket/demo%201%20shower%20thoughts.mp4",
		},
	}
	for _, tc := range tests {
		u, err := rawLinkURL(tc.in)
		require.NoError(t, err)
		require.Equal(t, tc.want, u.String())
	}
}
