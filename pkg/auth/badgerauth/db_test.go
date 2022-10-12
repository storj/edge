// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauth_test

import (
	"testing"
	"time"

	badger "github.com/outcaste-io/badger/v3"
	"github.com/spacemonkeygo/monkit/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"storj.io/common/testcontext"
	"storj.io/common/testrand"
	"storj.io/gateway-mt/pkg/auth/authdb"
	"storj.io/gateway-mt/pkg/auth/badgerauth"
	"storj.io/gateway-mt/pkg/auth/badgerauth/badgerauthtest"
	"storj.io/gateway-mt/pkg/auth/badgerauth/pb"
)

func TestKV(t *testing.T) {
	badgerauthtest.RunSingleNode(t, badgerauth.Config{}, func(ctx *testcontext.Context, t *testing.T, _ *zap.Logger, node *badgerauth.Node) {
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

			var r authdb.Record
			if i%2 == 0 {
				r = r1
			} else {
				r = r2
			}
			badgerauthtest.Put{KeyHash: kh, Record: &r}.Check(ctx, t, node)
		}

		for i := 0; i < 100; i++ {
			kh := authdb.KeyHash{byte(i)}

			var r authdb.Record
			if i%2 == 0 {
				r = r1
			} else {
				r = r2
			}
			badgerauthtest.Get{KeyHash: kh, Result: &r}.Check(ctx, t, node)
		}

		// Test deletion of expiring records:
		// (1) Insert expiring record that is impossible to expire during this test.
		maxTime := time.Unix(1<<62, 0)

		r3 := authdb.Record{
			SatelliteAddress:     "test satellite address 3",
			MacaroonHead:         []byte{'b', 'a'},
			EncryptedSecretKey:   []byte{'d', 'u', 'm'},
			EncryptedAccessGrant: []byte{'t', 's', 's'},
			ExpiresAt:            &maxTime,
			Public:               false,
		}

		badgerauthtest.Put{
			KeyHash: authdb.KeyHash{byte(200)},
			Record:  &r3,
		}.Check(ctx, t, node)

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

			badgerauthtest.Put{KeyHash: kh, Record: &r}.Check(ctx, t, node)
		}

		// (3) Check everything.
		for i := 0; i < 100; i++ {
			kh := authdb.KeyHash{byte(i)}

			var r authdb.Record
			if i%2 == 0 {
				r = r1
			} else {
				r = r2
			}
			badgerauthtest.Get{KeyHash: kh, Result: &r}.Check(ctx, t, node)
		}
		for i := 100; i < 200; i++ {
			kh := authdb.KeyHash{byte(i)}
			badgerauthtest.Get{KeyHash: kh}.Check(ctx, t, node)
		}
		badgerauthtest.Get{
			KeyHash: authdb.KeyHash{200},
			Result:  &r3,
		}.Check(ctx, t, node)
	})
}

func TestClockState(t *testing.T) {
	nodeID := badgerauth.NodeID{'t', 'e', 's', 't'}

	badgerauthtest.RunSingleNode(t, badgerauth.Config{
		ID: nodeID,
	}, func(ctx *testcontext.Context, t *testing.T, _ *zap.Logger, node *badgerauth.Node) {
		r := authdb.Record{
			SatelliteAddress:     "test",
			MacaroonHead:         []byte{'t', 'e', 's', 't'},
			EncryptedSecretKey:   []byte{'t', 'e', 's', 't'},
			EncryptedAccessGrant: []byte{'t', 'e', 's', 't'},
			Public:               true,
		}

		for i := 0; i < 100; i++ {
			kh := authdb.KeyHash{byte(i)}

			badgerauthtest.Put{KeyHash: kh, Record: &r}.Check(ctx, t, node)
			badgerauthtest.Get{KeyHash: kh, Result: &r}.Check(ctx, t, node)
		}

		badgerauthtest.Clock{NodeID: nodeID, Value: 100}.Check(t, node)

		badgerauthtest.Put{
			KeyHash: authdb.KeyHash{1},
			Record:  &r,
			Error:   badgerauth.Error.Wrap(badgerauth.ErrKeyAlreadyExists),
		}.Check(ctx, t, node)
		badgerauthtest.Put{
			KeyHash: authdb.KeyHash{'!', 'b', 'a', 'd', 'g', 'e', 'r', '!'},
			Record:  &r,
			Error:   badgerauth.Error.Wrap(badger.ErrInvalidKey),
		}.Check(ctx, t, node)

		badgerauthtest.Clock{NodeID: nodeID, Value: 100}.Check(t, node)

		expiresAt := time.Unix(time.Now().Unix(), 0).Add(24 * time.Hour)

		r2 := authdb.Record{
			SatelliteAddress:     "test",
			MacaroonHead:         []byte{'t', 'e', 's', 't'},
			EncryptedSecretKey:   []byte{'t', 'e', 's', 't'},
			EncryptedAccessGrant: []byte{'t', 'e', 's', 't'},
			ExpiresAt:            &expiresAt,
			Public:               true,
		}

		for i := 100; i < 200; i++ {
			kh := authdb.KeyHash{byte(i)}

			badgerauthtest.Put{KeyHash: kh, Record: &r2}.Check(ctx, t, node)
			badgerauthtest.Get{KeyHash: kh, Result: &r2}.Check(ctx, t, node)
		}

		badgerauthtest.Clock{NodeID: nodeID, Value: 200}.Check(t, node)
	})
}

func TestKVParallel(t *testing.T) {
	ops := 10000
	if testing.Short() {
		ops = 1000
	}

	badgerauthtest.RunSingleNode(t, badgerauth.Config{}, func(ctx *testcontext.Context, t *testing.T, _ *zap.Logger, node *badgerauth.Node) {
		db := node.UnderlyingDB()

		ctx.Go(func() error {
			for i := 0; i < ops; i++ {
				e := randTime(time.Hour)
				_ = db.Put(ctx, authdb.KeyHash{byte(testrand.Intn(100))}, &authdb.Record{
					SatelliteAddress:     "test",
					MacaroonHead:         []byte{1},
					EncryptedSecretKey:   []byte{2},
					EncryptedAccessGrant: []byte{3},
					ExpiresAt:            &e,
					Public:               false,
				})
			}
			return nil
		})
		ctx.Go(func() error {
			for i := 0; i < ops; i++ {
				e := randTime(time.Hour)
				_ = db.Put(ctx, authdb.KeyHash{byte(testrand.Intn(100))}, &authdb.Record{
					SatelliteAddress:     "tset",
					MacaroonHead:         []byte{4},
					EncryptedSecretKey:   []byte{5},
					EncryptedAccessGrant: []byte{6},
					ExpiresAt:            &e,
					Public:               true,
				})
			}
			return nil
		})
		ctx.Go(func() error {
			for i := 0; i < ops; i++ {
				_, _ = db.Get(ctx, authdb.KeyHash{byte(testrand.Intn(100))})
			}
			return nil
		})
		ctx.Wait()
	})
}

func randTime(d time.Duration) time.Time {
	return time.Now().Add(time.Duration(testrand.Int63n(int64(d))))
}

func TestDeleteUnusedAlwaysReturnsError(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	var err error

	badgerauthtest.RunSingleNode(t, badgerauth.Config{}, func(ctx *testcontext.Context, t *testing.T, _ *zap.Logger, node *badgerauth.Node) {
		db := node.UnderlyingDB()

		_, _, _, err = db.DeleteUnused(ctx, 0, 0, 0)
		assert.Error(t, err)
		_, _, _, err = db.DeleteUnused(ctx, 24*time.Hour, 10000, 1000)
		assert.Error(t, err)
	})

	//nolint: dogsled
	_, _, _, err = (&badgerauth.DB{}).DeleteUnused(ctx, 0, 0, 0)
	assert.Error(t, err)
	//nolint: dogsled
	_, _, _, err = (&badgerauth.DB{}).DeleteUnused(ctx, 24*time.Hour, 10000, 1000)
	assert.Error(t, err)
}

// TestBasicCycle sequentially tests the basic create → retrieve lifecycle of a
// single record, verifying fundamental KV interface guarantees.
func TestBasicCycle(t *testing.T) {
	id := badgerauth.NodeID{'b', 'a', 's', 'i', 'c'}
	keyHash := authdb.KeyHash{'t', 'e', 's', 't'}
	record := &authdb.Record{
		SatelliteAddress:     "test",
		MacaroonHead:         []byte{'t', 'e', 's', 't'},
		EncryptedSecretKey:   []byte{'t', 'e', 's', 't'},
		EncryptedAccessGrant: []byte{'t', 'e', 's', 't'},
		Public:               true,
	}

	badgerauthtest.RunSingleNode(t, badgerauth.Config{
		ID: id,
	}, func(ctx *testcontext.Context, t *testing.T, _ *zap.Logger, node *badgerauth.Node) {
		var currentReplicationLogEntries []badgerauthtest.ReplicationLogEntryWithTTL
		// verify replication log (empty)
		badgerauthtest.VerifyReplicationLog{
			Entries: currentReplicationLogEntries,
		}.Check(ctx, t, node)
		// put invalid key
		badgerauthtest.Put{
			KeyHash: authdb.KeyHash{'!', 'b', 'a', 'd', 'g', 'e', 'r', '!'},
			Record:  record,
			Error:   badgerauth.Error.Wrap(badger.ErrInvalidKey),
		}.Check(ctx, t, node)
		// verify replication log after invalid put
		badgerauthtest.VerifyReplicationLog{
			Entries: currentReplicationLogEntries,
		}.Check(ctx, t, node)
		// put
		badgerauthtest.Put{
			KeyHash: keyHash,
			Record:  record,
		}.Check(ctx, t, node)
		// verify replication log after put
		currentReplicationLogEntries = append(
			currentReplicationLogEntries,
			badgerauthtest.ReplicationLogEntryWithTTL{
				Entry: badgerauth.ReplicationLogEntry{id, 1, keyHash, pb.Record_CREATED},
			},
		)
		badgerauthtest.VerifyReplicationLog{
			Entries: currentReplicationLogEntries,
		}.Check(ctx, t, node)
		// put again
		badgerauthtest.Put{
			KeyHash: keyHash,
			Record:  record,
			Error:   badgerauth.Error.Wrap(badgerauth.ErrKeyAlreadyExists),
		}.Check(ctx, t, node)
		// verify replication log after invalid put
		badgerauthtest.VerifyReplicationLog{
			Entries: currentReplicationLogEntries,
		}.Check(ctx, t, node)
		// get unknown record
		badgerauthtest.Get{
			KeyHash: authdb.KeyHash{1},
		}.Check(ctx, t, node)
		// verify replication log after get
		badgerauthtest.VerifyReplicationLog{
			Entries: currentReplicationLogEntries,
		}.Check(ctx, t, node)
		// get
		badgerauthtest.Get{
			KeyHash: keyHash,
			Result:  record,
		}.Check(ctx, t, node)
		// verify replication log after get
		badgerauthtest.VerifyReplicationLog{
			Entries: currentReplicationLogEntries,
		}.Check(ctx, t, node)
		// get again
		badgerauthtest.Get{
			KeyHash: keyHash,
			Result:  record,
		}.Check(ctx, t, node)
		// verify replication log after get
		badgerauthtest.VerifyReplicationLog{
			Entries: currentReplicationLogEntries,
		}.Check(ctx, t, node)

		scope := "storj.io/gateway-mt/pkg/auth/badgerauth"
		c := monkit.Collect(monkit.ScopeNamed(scope))

		for name, count := range map[string]float64{
			"function,name=(*DB).PutAtTime,node_id=basic,scope=" + scope + " total":                             3,
			"function,name=(*DB).PutAtTime,node_id=basic,scope=" + scope + " errors":                            2,
			"function,name=(*DB).Get,node_id=basic,scope=" + scope + " total":                                   3,
			"function,name=(*DB).Get,node_id=basic,scope=" + scope + " errors":                                  0,
			"function,error_name=InvalidKey,name=(*DB).PutAtTime,node_id=basic,scope=" + scope + " count":       1,
			"function,error_name=KeyAlreadyExists,name=(*DB).PutAtTime,node_id=basic,scope=" + scope + " count": 1,
		} {
			assert.Equal(t, count, c[name], name)
		}
	})
}

// TestBasicCycleWithSafeExpiration is like TestBasicCycle, but it focuses on
// the behavior of actions when the record has an expiration time.
func TestBasicCycleWithExpiration(t *testing.T) {
	id := badgerauth.NodeID{'t', 'e', 's', 't', 'I', 'D'}

	badgerauthtest.RunSingleNode(t, badgerauth.Config{
		ID: id,
	}, func(ctx *testcontext.Context, t *testing.T, _ *zap.Logger, node *badgerauth.Node) {
		// construct current time used in this test so that it is stripped of
		// the number of nanoseconds and the monotonic clock reading.
		now := time.Unix(time.Now().Unix(), 0)
		expiresAt := now.Add(2 * time.Second)

		keyHash := authdb.KeyHash{'t', 'e', 's', 't'}
		record := &authdb.Record{
			SatelliteAddress:     "test",
			MacaroonHead:         []byte{'t', 'e', 's', 't'},
			EncryptedSecretKey:   []byte{'t', 'e', 's', 't'},
			EncryptedAccessGrant: []byte{'t', 'e', 's', 't'},
			ExpiresAt:            &expiresAt,
			Public:               true,
		}

		var currentReplicationLogEntries []badgerauthtest.ReplicationLogEntryWithTTL
		// verify replication log (empty)
		badgerauthtest.VerifyReplicationLog{
			Entries: currentReplicationLogEntries,
		}.Check(ctx, t, node)
		// put
		badgerauthtest.PutAtTime{
			KeyHash: keyHash,
			Record:  record,
			Time:    now,
		}.Check(ctx, t, node)
		// verify replication log after put
		currentReplicationLogEntries = append(
			currentReplicationLogEntries,
			badgerauthtest.ReplicationLogEntryWithTTL{
				Entry:     badgerauth.ReplicationLogEntry{id, 1, keyHash, pb.Record_CREATED},
				ExpiresAt: expiresAt,
			},
		)
		badgerauthtest.VerifyReplicationLog{
			Entries: currentReplicationLogEntries,
		}.Check(ctx, t, node)
		// get
		badgerauthtest.Get{
			KeyHash: keyHash,
			Result:  record,
		}.Check(ctx, t, node)
		// verify replication log after get
		badgerauthtest.VerifyReplicationLog{
			Entries: currentReplicationLogEntries,
		}.Check(ctx, t, node)
		// t+1
		time.Sleep(2 * time.Second)
		// get (t+1)
		badgerauthtest.Get{KeyHash: keyHash}.Check(ctx, t, node)
		// verify replication log after get (t+1)
		badgerauthtest.VerifyReplicationLog{}.Check(ctx, t, node)
	})
}

func TestOpenDB_BadNodeID(t *testing.T) {
	t.Parallel()

	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	log := zaptest.NewLogger(t)
	defer ctx.Check(log.Sync)
	cfg := badgerauth.Config{
		ID:         badgerauth.NodeID{'a'},
		FirstStart: true,
		Path:       ctx.File("badger.db"),
	}

	db, err := badgerauth.OpenDB(log, cfg)
	require.NoError(t, err)
	require.NoError(t, db.Close())

	cfg.ID = badgerauth.NodeID{'b'}
	db, err = badgerauth.OpenDB(log, cfg)
	require.Nil(t, db)
	require.Error(t, err)
	require.True(t, badgerauth.ErrDBStartedWithDifferentNodeID.Has(err))
}

func TestOpenDB_CheckFirstStart(t *testing.T) {
	t.Parallel()

	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	log := zaptest.NewLogger(t)
	defer ctx.Check(log.Sync)
	cfg := badgerauth.Config{
		FirstStart: false,
	}

	db, err := badgerauth.OpenDB(log, cfg)
	require.Nil(t, db)
	require.Error(t, err)
}
