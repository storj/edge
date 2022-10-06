// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauthmigration

import (
	"strconv"
	"testing"
	"time"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"storj.io/common/sync2"
	"storj.io/common/testcontext"
	"storj.io/gateway-mt/pkg/auth/authdb"
	"storj.io/gateway-mt/pkg/auth/badgerauth"
	"storj.io/gateway-mt/pkg/auth/badgerauth/badgerauthtest"
	"storj.io/gateway-mt/pkg/auth/sqlauth"
	"storj.io/private/dbutil/pgtest"
)

func TestKV_Postgres(t *testing.T) {
	testKV(t, pgtest.PickPostgres(t))
}

func TestKV_Cockroach(t *testing.T) {
	testKV(t, pgtest.PickCockroachAlt(t))
}

func testKV(t *testing.T, srcConnstr string) {
	badgerauthtest.RunSingleNode(t, badgerauth.Config{}, func(ctx *testcontext.Context, t *testing.T, log *zap.Logger, node *badgerauth.Node) {
		src, err := sqlauth.OpenTest(ctx, log, t.Name(), srcConnstr)
		require.NoError(t, err)
		defer ctx.Check(src.Close)

		kv := New(log, src, node, Config{})
		kv.mon = monkit.Default.ScopeNamed(t.Name())

		require.NoError(t, kv.PingDB(ctx))
		require.NoError(t, src.MigrateToLatest(ctx))

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
				require.NoError(t, kv.Put(ctx, kh, &r1))
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

			actual, err := kv.Get(ctx, kh)
			require.NoError(t, err)

			assert.Equal(t, &expected, actual)
		}

		// Test deletion of expiring records:
		// (1) Insert expiring record that is impossible to expire during this test.
		maxTime := time.Unix(1<<43, 0)

		r3 := authdb.Record{
			SatelliteAddress:     "test satellite address 3",
			MacaroonHead:         []byte{'b', 'a'},
			EncryptedSecretKey:   []byte{'d', 'u', 'm'},
			EncryptedAccessGrant: []byte{'t', 's', 's'},
			ExpiresAt:            &maxTime,
			Public:               false,
		}

		require.NoError(t, kv.Put(ctx, authdb.KeyHash{byte(200)}, &r3))

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

			require.NoError(t, kv.Put(ctx, kh, &r))
		}

		// sqlauth doesn't support record-level TTLs, so call DeleteUnused.
		_, _, _, err = src.DeleteUnused(ctx, time.Microsecond, 1000, 100)
		require.NoError(t, err)

		// (3) Check everything.
		for i := 0; i < 100; i++ {
			kh := authdb.KeyHash{byte(i)}

			var expected authdb.Record
			if i%2 == 0 {
				expected = r1
			} else {
				expected = r2
			}

			actual, err := kv.Get(ctx, kh)
			require.NoError(t, err)

			assert.Equal(t, &expected, actual)
		}

		for i := 100; i < 200; i++ {
			kh := authdb.KeyHash{byte(i)}

			actual, err := kv.Get(ctx, kh)
			require.NoError(t, err)

			assert.Nil(t, actual)
		}

		actual, err := kv.Get(ctx, authdb.KeyHash{200})
		require.NoError(t, err)

		assert.Equal(t, &r3, actual)

		scope := t.Name()
		c := monkit.Collect(monkit.ScopeNamed(scope))
		assert.EqualValues(t, 100, c["as_badgerauthmigration_destination_miss,scope="+scope+" total"])
		assert.EqualValues(t, 101, c["as_badgerauthmigration_destination_hit,scope="+scope+" total"])
	})
}

func TestMigrateToLatest_Postgres(t *testing.T) {
	testMigrateToLatest(t, pgtest.PickPostgres(t))
}

func TestMigrateToLatest_Cockroach(t *testing.T) {
	testMigrateToLatest(t, pgtest.PickCockroachAlt(t))
}

func testMigrateToLatest(t *testing.T, srcConnstr string) {
	badgerauthtest.RunSingleNode(t, badgerauth.Config{}, func(ctx *testcontext.Context, t *testing.T, log *zap.Logger, node *badgerauth.Node) {
		src, err := sqlauth.OpenTest(ctx, log, t.Name(), srcConnstr)
		require.NoError(t, err)
		defer ctx.Check(src.Close)

		kv := New(log, src, node, Config{MigrationSelectSize: 12})

		require.NoError(t, kv.PingDB(ctx))
		require.NoError(t, src.MigrateToLatest(ctx))

		var records []*authdb.Record

		for i := 0; i < 123; i++ {
			keyHash := authdb.KeyHash{byte(i)}
			expires := time.Unix(time.Now().Unix(), 0).Add(time.Hour)

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
				require.NoError(t, src.Invalidate(ctx, keyHash, "migration"+strconv.Itoa(i)))
			}
		}

		require.NoError(t, kv.MigrateToLatest(ctx))

		for i, r := range records {
			var (
				err    error
				result *authdb.Record
			)

			if i%10 == 0 {
				err = badgerauth.Error.Wrap(authdb.Invalid.New("migration%d", i))
			} else {
				result = r
			}

			badgerauthtest.Get{
				KeyHash: authdb.KeyHash{byte(i)},
				Result:  result,
				Error:   err,
			}.Check(ctx, t, node)
		}
	})
}

func TestPutWithSkewedTimes_Postgres(t *testing.T) {
	testPutWithSkewedTimes(t, pgtest.PickPostgres(t))
}

func TestPutWithSkewedTimes_Cockroach(t *testing.T) {
	testPutWithSkewedTimes(t, pgtest.PickCockroachAlt(t))
}

func testPutWithSkewedTimes(t *testing.T, srcConnstr string) {
	badgerauthtest.RunSingleNode(t, badgerauth.Config{}, func(ctx *testcontext.Context, t *testing.T, log *zap.Logger, node *badgerauth.Node) {
		src, err := sqlauth.OpenTest(ctx, log, t.Name(), srcConnstr)
		require.NoError(t, err)
		defer ctx.Check(src.Close)

		kv := New(log, src, node, Config{MigrationSelectSize: 1000})

		require.NoError(t, kv.PingDB(ctx))
		require.NoError(t, src.MigrateToLatest(ctx))

		createdAt := time.Unix(time.Now().Unix(), 0)

		keyHash := authdb.KeyHash{'a'}
		record := &authdb.Record{
			SatelliteAddress:     "migration",
			MacaroonHead:         []byte{'b'},
			EncryptedSecretKey:   []byte{'c'},
			EncryptedAccessGrant: []byte{'d'},
			ExpiresAt:            nil,
			Public:               true,
		}

		require.NoError(t, kv.dst.PutAtTime(ctx, keyHash, record, createdAt))
		require.True(t, sync2.Sleep(ctx, time.Second))
		require.NoError(t, kv.src.PutAtTime(ctx, keyHash, record, createdAt))

		// Inserting the same record into both stores with equal creation times
		// must result in success.
		require.NoError(t, kv.MigrateToLatest(ctx))

		keyHash = authdb.KeyHash{'e'}
		record = &authdb.Record{
			SatelliteAddress:     "noitargim",
			MacaroonHead:         []byte{'f'},
			EncryptedSecretKey:   []byte{'g'},
			EncryptedAccessGrant: []byte{'h'},
			ExpiresAt:            nil,
			Public:               false,
		}

		require.NoError(t, kv.dst.Put(ctx, keyHash, record))
		require.True(t, sync2.Sleep(ctx, time.Second))
		require.NoError(t, kv.src.Put(ctx, keyHash, record))

		// Inserting the same record into both stores with different creation
		// times must result in failure.
		require.Error(t, kv.MigrateToLatest(ctx))
	})
}

func TestGetExpired_Postgres(t *testing.T) {
	testGetExpired(t, pgtest.PickPostgres(t))
}

func TestGetExpired_Cockroach(t *testing.T) {
	testGetExpired(t, pgtest.PickCockroachAlt(t))
}

func testGetExpired(t *testing.T, srcConnstr string) {
	badgerauthtest.RunSingleNode(t, badgerauth.Config{}, func(ctx *testcontext.Context, t *testing.T, log *zap.Logger, node *badgerauth.Node) {
		src, err := sqlauth.OpenTest(ctx, log, t.Name(), srcConnstr)
		require.NoError(t, err)
		defer ctx.Check(src.Close)

		kv := New(log, src, node, Config{MigrationSelectSize: 1000})

		require.NoError(t, kv.PingDB(ctx))
		require.NoError(t, src.MigrateToLatest(ctx))

		now := time.Now()

		keyHash := authdb.KeyHash{'a'}
		record := &authdb.Record{
			SatelliteAddress:     "migration",
			MacaroonHead:         []byte{'b'},
			EncryptedSecretKey:   []byte{'c'},
			EncryptedAccessGrant: []byte{'d'},
			ExpiresAt:            &now,
			Public:               true,
		}

		require.NoError(t, kv.Put(ctx, keyHash, record))

		record, err = kv.Get(ctx, keyHash)
		require.NoError(t, err)
		require.Nil(t, record)
	})
}
