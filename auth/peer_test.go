// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package auth

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/testcontext"
)

// TestPeer_Close ensures that closing bare Peer with minimal config it needs to
// start will not panic and has released all the resources.
func TestPeer_Close(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	p, err := New(ctx, zaptest.NewLogger(t), Config{
		Endpoint:          "https://example.com",
		AllowedSatellites: []string{"https://www.storj.io/dcs-satellites"},
		KVBackend:         "memory://",
	}, "")
	require.NoError(t, err)

	require.NotPanics(t, func() {
		require.NoError(t, p.Close())
	})
}
