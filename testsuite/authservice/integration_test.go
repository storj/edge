// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package authservice_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"storj.io/common/errs2"
	"storj.io/common/fpath"
	"storj.io/common/grant"
	"storj.io/common/identity"
	"storj.io/common/identity/testidentity"
	"storj.io/common/macaroon"
	"storj.io/common/memory"
	"storj.io/common/storj"
	"storj.io/common/testcontext"
	"storj.io/common/testrand"
	internalAccess "storj.io/edge/internal/access"
	"storj.io/edge/internal/register"
	"storj.io/edge/pkg/auth"
	"storj.io/edge/pkg/auth/authdb"
	"storj.io/edge/pkg/auth/spannerauth"
	"storj.io/edge/pkg/auth/spannerauth/spannerauthtest"
	"storj.io/edge/pkg/authclient"
	"storj.io/edge/pkg/tierquery"
	"storj.io/storj/private/testplanet"
	"storj.io/storj/satellite"
	"storj.io/storj/satellite/console"
	"storj.io/uplink"
	privateAccess "storj.io/uplink/private/access"
)

func TestAuthservice(t *testing.T) {
	t.Parallel()

	testSatellite := testrand.NodeID().String() + "@satellite.test"

	runEnvironment(t, reconfigure{
		auth: func(config *auth.Config) {
			config.AllowedSatellites = append(config.AllowedSatellites, testSatellite)
		},
	}, func(t *testing.T, ctx *testcontext.Context, env *environment) {
		serialized, err := env.planet.Uplinks[0].Access[env.planet.Satellites[0].ID()].Serialize()
		require.NoError(t, err)

		runTest := func(addr, serialized string, test func(resp authclient.AuthServiceResponse)) {
			creds, err := register.Access(ctx, addr, serialized, false)
			require.NoError(t, err)

			resp, err := env.authClient.Resolve(ctx, creds.AccessKeyID, "")
			require.NoError(t, err)

			test(resp)
		}

		test := func(resp authclient.AuthServiceResponse) {
			require.Equal(t, serialized, resp.AccessGrant)
			require.Equal(t, env.planet.Uplinks[0].Projects[0].PublicID.String(), resp.PublicProjectID)
		}

		runTest("http://"+env.auth.Address(), serialized, test)
		runTest("drpc://"+env.auth.DRPCAddress(), serialized, test)

		apiKey, err := macaroon.NewAPIKey([]byte("secret"))
		require.NoError(t, err)

		ag := grant.Access{
			SatelliteAddress: testSatellite,
			APIKey:           apiKey,
			EncAccess:        grant.NewEncryptionAccess(),
		}
		testSatelliteAccess, err := ag.Serialize()
		require.NoError(t, err)

		nonExistentSatelliteTest := func(resp authclient.AuthServiceResponse) {
			require.Equal(t, testSatelliteAccess, resp.AccessGrant)
			require.Equal(t, "", resp.PublicProjectID)
		}

		runTest("http://"+env.auth.Address(), testSatelliteAccess, nonExistentSatelliteTest)
		runTest("drpc://"+env.auth.DRPCAddress(), testSatelliteAccess, nonExistentSatelliteTest)
	})
}

// TODO(jeremy, artur): this test has a potential to be flaky due to the
// time-based nature of the test.
func TestAccessExpiration(t *testing.T) {
	t.Parallel()

	tempPath := t.TempDir()
	identConfig := identity.Config{
		CertPath: filepath.Join(tempPath, "identity.crt"),
		KeyPath:  filepath.Join(tempPath, "identity.key"),
	}

	ident := testidentity.MustPregeneratedIdentity(0, storj.LatestIDVersion())
	require.NoError(t, identConfig.Save(ident))

	const maxAccessDuration = 5 * time.Minute
	runEnvironment(t, reconfigure{
		testPlanet: testplanet.Reconfigure{
			Satellite: func(log *zap.Logger, index int, config *satellite.Config) {
				url, err := storj.ParseNodeURL(ident.ID.String() + "@")
				require.NoError(t, err)

				config.Userinfo.Enabled = true
				config.Userinfo.AllowedPeers = storj.NodeURLs{url}
			},
		},
		auth: func(config *auth.Config) {
			config.FreeTierAccessLimit = authdb.FreeTierAccessLimitConfig{
				MaxDuration: maxAccessDuration,
				TierQuery: tierquery.Config{
					Identity:        identConfig,
					CacheExpiration: 0,
					CacheCapacity:   0,
				},
			}
		},
	}, func(t *testing.T, ctx *testcontext.Context, env *environment) {
		sat := env.planet.Satellites[0]
		up := env.planet.Uplinks[0]

		unrestricted := up.Access[sat.ID()]

		unrestrictedSerialized, err := unrestricted.Serialize()
		require.NoError(t, err)

		longDurationExpiration := time.Now().Add(maxAccessDuration).Add(5 * time.Minute)
		longDuration, err := privateAccess.Share(unrestricted,
			privateAccess.WithAllPermissions(),
			privateAccess.NotAfter(longDurationExpiration),
		)
		require.NoError(t, err)

		longDurationSerialized, err := longDuration.Serialize()
		require.NoError(t, err)

		type accessTestCase struct {
			public                       bool
			serializedAccess             string
			expectedExpiration           *time.Time
			expectedRestrictedExpiration *time.Time
		}

		runTests := func(t *testing.T, testCase accessTestCase) {
			for _, tt := range []struct{ name, addr string }{
				{name: "HTTP", addr: "http://" + env.auth.Address()},
				{name: "DRPC", addr: "drpc://" + env.auth.DRPCAddress()},
			} {
				t.Run(tt.name, func(t *testing.T) {
					creds, err := register.Access(ctx, tt.addr, testCase.serializedAccess, testCase.public)
					require.NoError(t, err)

					if testCase.expectedRestrictedExpiration != nil {
						require.NotNil(t, creds.FreeTierRestrictedExpiration)
						require.WithinDuration(t, *testCase.expectedRestrictedExpiration, *creds.FreeTierRestrictedExpiration, time.Second)
					} else {
						require.Nil(t, creds.FreeTierRestrictedExpiration)
					}

					resp, err := env.authClient.Resolve(ctx, creds.AccessKeyID, "")
					require.NoError(t, err)

					respAccess, err := uplink.ParseAccess(resp.AccessGrant)
					require.NoError(t, err)

					apiKey := privateAccess.APIKey(respAccess)
					expiration, err := internalAccess.APIKeyExpiration(apiKey)
					require.NoError(t, err)

					if testCase.expectedExpiration != nil {
						require.NotNil(t, expiration)
						require.WithinDuration(t, *testCase.expectedExpiration, *expiration, time.Second)
					} else {
						require.Nil(t, expiration)
					}
				})
			}
		}

		t.Run("Free tier", func(t *testing.T) {
			t.Run("Unrestricted access", func(t *testing.T) {
				expiration := time.Now().Add(maxAccessDuration)
				runTests(t, accessTestCase{
					public:                       false,
					serializedAccess:             unrestrictedSerialized,
					expectedExpiration:           nil,
					expectedRestrictedExpiration: nil,
				})
				runTests(t, accessTestCase{
					public:                       true,
					serializedAccess:             unrestrictedSerialized,
					expectedExpiration:           &expiration,
					expectedRestrictedExpiration: &expiration,
				})
			})

			t.Run("Access with prohibited expiration", func(t *testing.T) {
				expiration := time.Now().Add(maxAccessDuration)
				runTests(t, accessTestCase{
					public:                       false,
					serializedAccess:             longDurationSerialized,
					expectedExpiration:           &longDurationExpiration,
					expectedRestrictedExpiration: nil,
				})
				runTests(t, accessTestCase{
					public:                       true,
					serializedAccess:             longDurationSerialized,
					expectedExpiration:           &expiration,
					expectedRestrictedExpiration: &expiration,
				})
			})

			t.Run("Access with allowed expiration", func(t *testing.T) {
				expiration := time.Now().Add(maxAccessDuration / 2)

				access, err := privateAccess.Share(unrestricted,
					privateAccess.WithAllPermissions(),
					privateAccess.NotAfter(expiration),
				)
				require.NoError(t, err)

				serialized, err := access.Serialize()
				require.NoError(t, err)

				runTests(t, accessTestCase{
					public:                       false,
					serializedAccess:             serialized,
					expectedExpiration:           &expiration,
					expectedRestrictedExpiration: nil,
				})
				runTests(t, accessTestCase{
					public:                       true,
					serializedAccess:             serialized,
					expectedExpiration:           &expiration,
					expectedRestrictedExpiration: nil,
				})
			})
		})

		t.Run("Paid tier", func(t *testing.T) {
			paidUser := console.PaidUser
			require.NoError(t, sat.DB.Console().Users().Update(ctx, up.Projects[0].Owner.ID, console.UpdateUserRequest{
				Kind: &paidUser,
			}))

			t.Run("Unrestricted access", func(t *testing.T) {
				runTests(t, accessTestCase{
					public:                       false,
					serializedAccess:             unrestrictedSerialized,
					expectedExpiration:           nil,
					expectedRestrictedExpiration: nil,
				})
				runTests(t, accessTestCase{
					public:                       true,
					serializedAccess:             unrestrictedSerialized,
					expectedExpiration:           nil,
					expectedRestrictedExpiration: nil,
				})
			})

			t.Run("Access with duration longer than free-tier limit", func(t *testing.T) {
				runTests(t, accessTestCase{
					public:                       false,
					serializedAccess:             longDurationSerialized,
					expectedExpiration:           &longDurationExpiration,
					expectedRestrictedExpiration: nil,
				})
				runTests(t, accessTestCase{
					public:                       true,
					serializedAccess:             longDurationSerialized,
					expectedExpiration:           &longDurationExpiration,
					expectedRestrictedExpiration: nil,
				})
			})
		})
	})
}

type environment struct {
	planet     *testplanet.Planet
	auth       *auth.Peer
	authClient *authclient.AuthClient
}

type reconfigure struct {
	testPlanet testplanet.Reconfigure
	auth       func(config *auth.Config)
}

func runEnvironment(t *testing.T, recfg reconfigure, fn func(t *testing.T, ctx *testcontext.Context, env *environment)) {
	testplanet.Run(t, testplanet.Config{
		SatelliteCount: 1, StorageNodeCount: 0, UplinkCount: 1,
		Reconfigure: recfg.testPlanet,
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

		testSatellite := testrand.NodeID().String() + "@satellite.test"

		authConfig := auth.Config{
			Endpoint:      "http://localhost:1234",
			AuthToken:     []string{"super-secret"},
			POSTSizeLimit: 4 * memory.KiB,
			AllowedSatellites: []string{
				planet.Satellites[0].NodeURL().String(),
				testSatellite,
			},
			KVBackend:      "spanner://",
			ListenAddr:     ":0",
			DRPCListenAddr: ":0",
			Spanner: spannerauth.Config{
				DatabaseName: "projects/P/instances/I/databases/D",
				Address:      server.Addr,
			},
			RetrievePublicProjectID: true,
		}

		if recfg.auth != nil {
			recfg.auth(&authConfig)
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

		fn(t, ctx, &environment{
			planet:     planet,
			auth:       auth,
			authClient: authClient,
		})
	})
}
