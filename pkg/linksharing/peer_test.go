// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package linksharing

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/gateway-mt/pkg/httpserver"
	"storj.io/gateway-mt/pkg/linksharing/sharing"
)

func TestNewPeerMinimalConfig(t *testing.T) {
	_, err := New(zaptest.NewLogger(t), Config{
		Server: httpserver.Config{
			Address: "127.0.0.1:0",
		},
		Handler: sharing.Config{
			URLBases:  []string{"http://localhost:20020"},
			Templates: "./web",
		},
	})
	require.NoError(t, err)
}
