// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package authservice_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/errs2"
	"storj.io/common/fpath"
	"storj.io/common/memory"
	"storj.io/common/testcontext"
	"storj.io/edge/internal/register"
	"storj.io/edge/pkg/auth"
	"storj.io/edge/pkg/auth/spannerauth"
	"storj.io/edge/pkg/auth/spannerauth/spannerauthtest"
	"storj.io/edge/pkg/authclient"
	"storj.io/storj/private/testplanet"
)

func TestAuthservice(t *testing.T) {
	t.Parallel()

	testplanet.Run(t, testplanet.Config{
		SatelliteCount:   1,
		StorageNodeCount: 0,
		UplinkCount:      1,
	}, func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet) {
		logger := zaptest.NewLogger(t)
		defer ctx.Check(logger.Sync)

		server, err := spannerauthtest.ConfigureTestServer(ctx, logger)
		require.NoError(t, err)
		defer server.Close()

		db, err := spannerauth.Open(ctx, logger, spannerauth.Config{
			DatabaseName: "projects/P/instances/I/databases/D",
			Address:      server.Addr,
		})
		require.NoError(t, err)
		defer ctx.Check(db.Close)

		authConfig := auth.Config{
			Endpoint:          "http://localhost:1234",
			AuthToken:         []string{"super-secret"},
			POSTSizeLimit:     4 * memory.KiB,
			AllowedSatellites: []string{planet.Satellites[0].NodeURL().String()},
			KVBackend:         "spanner://",
			ListenAddr:        ":0",
			DRPCListenAddr:    ":0",
			Spanner: spannerauth.Config{
				DatabaseName: "projects/P/instances/I/databases/D",
				Address:      server.Addr,
			},
			RetrievePublicProjectID: true,
		}

		auth, err := auth.New(ctx, logger.Named("auth"), authConfig, fpath.ApplicationDir("storj", "authservice"))
		require.NoError(t, err)

		// auth peer needs to be canceled to shut the servers down.
		cancelCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		ctx.Go(func() error {
			defer ctx.Check(auth.Close)
			return errs2.IgnoreCanceled(auth.Run(cancelCtx))
		})

		authClient := authclient.New(authclient.Config{
			BaseURL: "http://" + auth.Address(),
			Token:   "super-secret",
		})

		serialized, err := planet.Uplinks[0].Access[planet.Satellites[0].ID()].Serialize()
		require.NoError(t, err)

		runTest := func(addr string) {
			creds, err := register.Access(ctx, addr, serialized, false)
			require.NoError(t, err)

			resp, err := authClient.Resolve(ctx, creds.AccessKeyID, "")
			require.NoError(t, err)

			require.Equal(t, serialized, resp.AccessGrant)
			require.Equal(t, planet.Uplinks[0].Projects[0].PublicID.String(), resp.PublicProjectID)
		}

		runTest("http://" + auth.Address())
		runTest("drpc://" + auth.DRPCAddress())
	})
}
