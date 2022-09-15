// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauth

import (
	"testing"

	badger "github.com/outcaste-io/badger/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/testrand"
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
