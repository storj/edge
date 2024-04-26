// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package linksharing

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/edge/pkg/httpserver"
	"storj.io/edge/pkg/linksharing/sharing"
	"storj.io/edge/pkg/linksharing/sharing/assets"
)

func TestNewPeerMinimalConfig(t *testing.T) {
	_, err := New(zaptest.NewLogger(t), Config{
		Server: httpserver.Config{
			Address: "127.0.0.1:0",
		},
		Handler: sharing.Config{
			Assets:        assets.FS(),
			ListPageLimit: 1,
			URLBases:      []string{"http://localhost:20020"},
		},
	})
	require.NoError(t, err)
}
