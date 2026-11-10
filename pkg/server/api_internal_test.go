// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSlowDownRetryAfter(t *testing.T) {
	// t.Setenv restores the variable after the test, which os.Unsetenv doesn't.
	t.Setenv("STORJ_MINIO_RETRY_AFTER", "")
	require.NoError(t, os.Unsetenv("STORJ_MINIO_RETRY_AFTER"))
	retryAfter, err := slowDownRetryAfter()
	require.NoError(t, err)
	require.Equal(t, 12*time.Second, retryAfter)

	t.Setenv("STORJ_MINIO_RETRY_AFTER", "30")
	retryAfter, err = slowDownRetryAfter()
	require.NoError(t, err)
	require.Equal(t, 30*time.Second, retryAfter)

	for _, value := range []string{"", "1.5", "Wed, 21 Oct 2015 07:28:00 GMT"} {
		t.Setenv("STORJ_MINIO_RETRY_AFTER", value)
		_, err = slowDownRetryAfter()
		require.Error(t, err, value)
	}
}
