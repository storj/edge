// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"storj.io/common/fpath"
	"storj.io/common/testcontext"
)

func TestSetInMemory(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	req, err := http.NewRequestWithContext(ctx, "GET", "", nil)
	require.NoError(t, err)

	verify := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, inmemory, ok := fpath.GetTempData(r.Context())
		require.True(t, ok)
		require.True(t, inmemory)
	})

	SetInMemory(verify).ServeHTTP(nil, req)
}
