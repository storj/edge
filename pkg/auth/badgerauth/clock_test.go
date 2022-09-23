// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauth

import (
	"testing"
	"time"

	badger "github.com/outcaste-io/badger/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/testcontext"
	"storj.io/common/testrand"
	"storj.io/gateway-mt/pkg/auth/authdb"
	"storj.io/gateway-mt/pkg/auth/badgerauth/pb"
)

func TestAdvanceClock(t *testing.T) {
	t.Parallel()

	db, err := OpenDB(zaptest.NewLogger(t), Config{FirstStart: true})
	require.NoError(t, err)
	udb := db.UnderlyingDB()

	id := NodeID{'i', 'd', '1'}
	var counter Clock
	require.NoError(t, udb.Update(func(txn *badger.Txn) error {
		for i := 0; i < 1234; i++ {
			fromNext, err := advanceClock(txn, id)
			require.NoError(t, err)
			fromRead, err := ReadClock(txn, id)
			require.NoError(t, err)
			assert.Equal(t, fromRead, fromNext)
			counter++
		}
		v, err := ReadClock(txn, id)
		assert.NoError(t, err)
		assert.Equal(t, counter, v)
		return err
	}))

	require.NoError(t, udb.View(func(txn *badger.Txn) error {
		v, err := ReadClock(txn, id)
		assert.NoError(t, err)
		assert.Equal(t, counter, v)
		return err
	}))

	assert.ErrorIs(t, udb.View(func(txn *badger.Txn) error {
		_, err := ReadClock(txn, NodeID{'i', 'd', '2'})
		return err
	}), badger.ErrKeyNotFound)
}

func TestReadAvailableClocks(t *testing.T) {
	t.Parallel()

	db, err := OpenDB(zaptest.NewLogger(t), Config{FirstStart: true})
	require.NoError(t, err)
	udb := db.UnderlyingDB()

	expectedClocks := make(map[NodeID]Clock)

	for i := 0; i < 10; i++ {
		var id NodeID
		require.NoError(t, id.SetBytes(testrand.BytesInt(32)))
		expectedClocks[id] = Clock(testrand.Int63n(10) + 1)
	}

	require.NoError(t, udb.Update(func(txn *badger.Txn) error {
		for id, count := range expectedClocks {
			for i := Clock(0); i < count; i++ {
				if _, err = advanceClock(txn, id); err != nil {
					return err
				}
			}
		}
		return nil
	}))

	var actualClocks map[NodeID]Clock

	require.NoError(t, udb.View(func(txn *badger.Txn) error {
		actualClocks, err = readAvailableClocks(txn)
		return err
	}))

	assert.Equal(t, expectedClocks, actualClocks)
}

var readAvailableClocksResult map[NodeID]Clock

func BenchmarkReadAvailableClocks(b *testing.B) {
	ctx := testcontext.New(b)
	defer ctx.Cleanup()

	logger := zaptest.NewLogger(b)
	defer ctx.Check(logger.Sync)

	db, err := OpenDB(logger, Config{
		ID:         NodeID{0},
		FirstStart: true,
		Path:       ctx.Dir("database"),
	})
	require.NoError(b, err)
	defer ctx.Check(db.Close)

	// Prepare data in similar proportions as they are in prod:
	//
	// Batch 1x, 2x, and 100x records for IDs 0, 1, and 2 (representing regions)
	// into 10 TXs because they won't fit into one TX.
	udb := db.UnderlyingDB()

	for i := 0; i < 10; i++ {
		require.NoError(b, udb.Update(func(txn *badger.Txn) error {
			for j := 0; j < 3; j++ {
				if err = ensureClock(txn, NodeID{byte(j)}); err != nil {
					return err
				}
			}

			record := &pb.Record{
				CreatedAtUnix:        time.Now().Unix(),
				Public:               true,
				SatelliteAddress:     "bench",
				MacaroonHead:         []byte{'b', 'e', 'n', 'c', 'h'},
				ExpiresAtUnix:        time.Now().Add(time.Hour).Unix(),
				EncryptedSecretKey:   []byte{'b', 'e', 'n', 'c', 'h'},
				EncryptedAccessGrant: []byte{'b', 'e', 'n', 'c', 'h'},
				State:                pb.Record_CREATED,
			}

			for j := 0; j < 200; j++ {
				var keyHash authdb.KeyHash
				if err = keyHash.SetBytes(testrand.RandAlphaNumeric(32)); err != nil {
					return err
				}
				record.CreatedAtUnix = time.Now().Unix()
				record.ExpiresAtUnix = time.Now().Add(time.Hour).Unix()
				if err = InsertRecord(logger, txn, NodeID{0}, keyHash, record); err != nil {
					return err
				}
			}
			for j := 0; j < 400; j++ {
				var keyHash authdb.KeyHash
				if err = keyHash.SetBytes(testrand.RandAlphaNumeric(32)); err != nil {
					return err
				}
				record.CreatedAtUnix = time.Now().Unix()
				record.ExpiresAtUnix = time.Now().Add(time.Hour).Unix()
				if err = InsertRecord(logger, txn, NodeID{1}, keyHash, record); err != nil {
					return err
				}
			}
			for j := 0; j < 20000; j++ {
				var keyHash authdb.KeyHash
				if err = keyHash.SetBytes(testrand.RandAlphaNumeric(32)); err != nil {
					return err
				}
				record.CreatedAtUnix = time.Now().Unix()
				record.ExpiresAtUnix = time.Now().Add(time.Hour).Unix()
				if err = InsertRecord(logger, txn, NodeID{2}, keyHash, record); err != nil {
					return err
				}
			}

			return nil
		}))
	}

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		var result map[NodeID]Clock
		// Always record the result of readAvailableClocks to prevent the
		// compiler eliminating the function call.
		require.NoError(b, udb.View(func(txn *badger.Txn) error {
			result, err = readAvailableClocks(txn)
			return err
		}))
		// Always store the result to a package level variable so the compiler
		// cannot eliminate the Benchmark itself.
		readAvailableClocksResult = result
	}
}
