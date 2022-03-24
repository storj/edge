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
	l := NewLogger(zaptest.NewLogger(t).Sugar())

	opt := badger.DefaultOptions("").WithInMemory(true).WithLogger(l)
	db, err := badger.Open(opt)
	require.NoError(t, err)

	id := NodeID("id")
	var counter Clock
	require.NoError(t, db.Update(func(txn *badger.Txn) error {
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

	require.NoError(t, db.View(func(txn *badger.Txn) error {
		v, err := ReadClock(txn, id)
		assert.NoError(t, err)
		assert.Equal(t, counter, v)
		return err
	}))

	assert.ErrorIs(t, db.View(func(txn *badger.Txn) error {
		_, err := ReadClock(txn, NodeID("A different ID"))
		return err
	}), badger.ErrKeyNotFound)
}
