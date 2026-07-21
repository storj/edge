// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package auth

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/testcontext"
)

func TestOpenStorageUnknownScheme(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	_, err := OpenStorage(ctx, zaptest.NewLogger(t), Config{KVBackend: "nope://x"})
	require.Error(t, err)
}
