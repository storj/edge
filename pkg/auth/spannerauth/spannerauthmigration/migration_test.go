// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package spannerauthmigration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"storj.io/common/testcontext"
	"storj.io/common/testrand"
	"storj.io/edge/pkg/auth/authdb"
	"storj.io/edge/pkg/auth/badgerauth"
	"storj.io/edge/pkg/auth/badgerauth/badgerauthtest"
	"storj.io/edge/pkg/auth/badgerauth/pb"
	"storj.io/edge/pkg/auth/spannerauth"
	"storj.io/edge/pkg/auth/spannerauth/spannerauthtest"
)

func TestStorage(t *testing.T) {
	badgerauthtest.RunSingleNode(t, badgerauth.Config{}, func(ctx *testcontext.Context, t *testing.T, log *zap.Logger, node *badgerauth.Node) {
		src := node

		server, err := spannerauthtest.ConfigureTestServer(ctx, log)
		require.NoError(t, err)
		defer server.Close()

		dst, err := spannerauth.Open(ctx, log, spannerauth.Config{
			DatabaseName: "projects/P/instances/I/databases/D",
			Address:      server.Addr,
		})
		require.NoError(t, err)
		defer ctx.Check(dst.Close)

		s := New(log, src, dst)
		s.mon = monkit.Default.ScopeNamed(t.Name())

		require.NoError(t, s.HealthCheck(ctx))

		r1 := authdb.Record{
			SatelliteAddress:     "test satellite address 1",
			MacaroonHead:         []byte{'v', 'e', 'r', 'y'},
			EncryptedSecretKey:   []byte{'g', 'o', 'o', 'd'},
			EncryptedAccessGrant: []byte{'t', 'e', 's', 't'},
			ExpiresAt:            nil,
			Public:               true,
		}
		r2 := authdb.Record{
			SatelliteAddress:     "test satellite address 2",
			MacaroonHead:         []byte{'t', 'e', 's', 't'},
			EncryptedSecretKey:   []byte{'g', 'o', 'o', 'd'},
			EncryptedAccessGrant: []byte{'v', 'e', 'r', 'y'},
			ExpiresAt:            nil,
			Public:               true,
		}

		for i := 0; i < 100; i++ {
			kh := authdb.KeyHash{byte(i)}

			if i%2 == 0 {
				require.NoError(t, s.Put(ctx, kh, &r1))
			} else {
				require.NoError(t, src.Put(ctx, kh, &r2))
			}
		}

		for i := 0; i < 100; i++ {
			kh := authdb.KeyHash{byte(i)}

			var expected authdb.Record
			if i%2 == 0 {
				expected = r1
			} else {
				expected = r2
			}

			actual, err := s.Get(ctx, kh)
			require.NoError(t, err)

			assert.Equal(t, &expected, actual)
		}

		// Test deletion of expiring records:
		// (1) Insert expiring record that is impossible to expire during this test.
		expires := time.Now().UTC().Add(time.Hour)

		r3 := authdb.Record{
			SatelliteAddress:     "test satellite address 3",
			MacaroonHead:         []byte{'b', 'a'},
			EncryptedSecretKey:   []byte{'d', 'u', 'm'},
			EncryptedAccessGrant: []byte{'t', 's', 's'},
			ExpiresAt:            &expires,
			Public:               false,
		}

		require.NoError(t, s.Put(ctx, authdb.KeyHash{byte(200)}, &r3))

		now := time.Unix(time.Now().Unix(), 0)
		r := authdb.Record{
			SatelliteAddress:     "test",
			MacaroonHead:         []byte{'t', 'e', 's', 't'},
			EncryptedSecretKey:   []byte{'t', 'e', 's', 't'},
			EncryptedAccessGrant: []byte{'t', 'e', 's', 't'},
			ExpiresAt:            &now,
			Public:               true,
		}

		// (2) Insert the rest of the expiring records.
		for i := 100; i < 200; i++ {
			kh := authdb.KeyHash{byte(i)}

			require.NoError(t, s.Put(ctx, kh, &r))
		}

		// (3) Check everything.
		for i := 0; i < 100; i++ {
			kh := authdb.KeyHash{byte(i)}

			var expected authdb.Record
			if i%2 == 0 {
				expected = r1
			} else {
				expected = r2
			}

			actual, err := s.Get(ctx, kh)
			require.NoError(t, err)

			assert.Equal(t, &expected, actual)
		}

		for i := 100; i < 200; i++ {
			kh := authdb.KeyHash{byte(i)}

			actual, err := s.Get(ctx, kh)
			require.NoError(t, err)

			assert.Nil(t, actual)
		}

		actual, err := s.Get(ctx, authdb.KeyHash{200})
		require.NoError(t, err)

		assert.Equal(t, &r3, actual)

		scope := t.Name()
		c := monkit.Collect(monkit.ScopeNamed(scope))
		assert.EqualValues(t, 100, c["as_spannerauthmigration_destination_miss,scope="+scope+" total"])
		assert.EqualValues(t, 101, c["as_spannerauthmigration_destination_hit,scope="+scope+" total"])
	})
}

func TestContextCanceledHandling(t *testing.T) {
	badgerauthtest.RunSingleNode(t, badgerauth.Config{}, func(ctx *testcontext.Context, t *testing.T, log *zap.Logger, node *badgerauth.Node) {
		src := node

		server, err := spannerauthtest.ConfigureTestServer(ctx, log)
		require.NoError(t, err)
		defer server.Close()

		dst, err := spannerauth.Open(ctx, log, spannerauth.Config{
			DatabaseName: "projects/P/instances/I/databases/D",
			Address:      server.Addr,
		})
		require.NoError(t, err)
		defer ctx.Check(dst.Close)

		s := New(log, src, dst)
		s.mon = monkit.Default.ScopeNamed(t.Name())

		require.NoError(t, s.HealthCheck(ctx))

		ctxWithCancel, cancel := context.WithCancel(ctx)
		cancel()

		var k authdb.KeyHash
		testrand.Read(k[:])
		err = s.Put(ctxWithCancel, k, &authdb.Record{})
		require.True(t, Error.Has(err))
		require.ErrorIs(t, err, context.Canceled)
		_, err = s.Get(ctxWithCancel, k)
		require.True(t, Error.Has(err))
		require.ErrorIs(t, err, context.Canceled)
	})
}

func TestMigration(t *testing.T) {
	badgerauthtest.RunSingleNode(t, badgerauth.Config{}, func(ctx *testcontext.Context, t *testing.T, log *zap.Logger, node *badgerauth.Node) {
		src := node
		admin := badgerauth.NewAdmin(node.UnderlyingDB())

		server, err := spannerauthtest.ConfigureTestServer(ctx, log)
		require.NoError(t, err)
		defer server.Close()

		dst, err := spannerauth.Open(ctx, log, spannerauth.Config{
			DatabaseName: "projects/P/instances/I/databases/D",
			Address:      server.Addr,
		})
		require.NoError(t, err)
		defer ctx.Check(dst.Close)

		s := New(log, src, dst)

		var records []*authdb.Record
		for i := 0; i < 123; i++ {
			keyHash := authdb.KeyHash{byte(i)}
			expires := time.Unix(time.Now().Unix(), 0).Add(time.Hour).UTC()

			record := &authdb.Record{
				SatelliteAddress:     "migration",
				MacaroonHead:         []byte{'m', 'i', 'g', 'r', 'a', 't', 'i', 'o', 'n', byte(i)},
				EncryptedSecretKey:   []byte{'m', 'i', 'g', 'r', 'a', 't', 'i', 'o', 'n', byte(i)},
				EncryptedAccessGrant: []byte{'m', 'i', 'g', 'r', 'a', 't', 'i', 'o', 'n', byte(i)},
				ExpiresAt:            &expires,
				Public:               true,
			}
			records = append(records, record)
			require.NoError(t, src.Put(ctx, keyHash, record))

			if i%10 == 0 {
				_, err := admin.InvalidateRecord(ctx, &pb.InvalidateRecordRequest{
					Key:    keyHash.Bytes(),
					Reason: fmt.Sprintf("migration%d", i),
				})
				require.NoError(t, err)
			}
		}

		require.NoError(t, s.MigrateToLatest(ctx))

		for i, record := range records {
			got, err := dst.Get(ctx, authdb.KeyHash{byte(i)})
			require.NoError(t, err)

			// invalidated records don't get migrated.
			if i%10 == 0 {
				assert.Nil(t, got)
			} else {
				assert.Equal(t, record, got)
			}
		}
	})
}
