// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauth

import (
	"testing"

	badger "github.com/outcaste-io/badger/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestAdvanceClock(t *testing.T) {
	db, err := OpenDB(zaptest.NewLogger(t), Config{})
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
