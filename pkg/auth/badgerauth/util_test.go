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
)

func TestNextReadClockValue(t *testing.T) {
	l := NewLogger(zaptest.NewLogger(t).Sugar())

	opt := badger.DefaultOptions("").WithInMemory(true).WithLogger(l)
	db, err := badger.Open(opt)
	require.NoError(t, err, "Open")

	id := []byte("id")
	var counter uint64
	require.NoError(t, db.Update(func(txn *badger.Txn) error {
		for i := 0; i < 1234; i++ {
			fromNext, err := nextClockValue(txn, id)
			require.NoError(t, err, "nextClockValue")
			fromRead, err := readClockValue(txn, id)
			require.NoError(t, err, "readClockValue after nextClockValue")
			assert.Equal(t, fromRead, fromNext)
			counter++
		}
		v, err := readClockValue(txn, id)
		assert.NoError(t, err, "readClockValue (read/write txn)")
		assert.Equal(t, counter, v)
		return err
	}))
	require.NoError(t, db.View(func(txn *badger.Txn) error {
		v, err := readClockValue(txn, id)
		assert.NoError(t, err, "readClockValue (read-only txn)")
		assert.Equal(t, counter, v)
		return err
	}))

	assert.ErrorIs(t, db.View(func(txn *badger.Txn) error {
		_, err := readClockValue(txn, []byte("A different ID"))
		return err
	}), badger.ErrKeyNotFound)
}

func TestTimestampToTime(t *testing.T) {
	// Construct current time used in this test so that it is stripped of the
	// number of nanoseconds and the monotonic clock reading.
	now := time.Unix(time.Now().Unix(), 0)
	assert.Equal(t, (*time.Time)(nil), timestampToTime(0))
	assert.Equal(t, &now, timestampToTime(now.Unix()))
}

func TestTimeToTimestamp(t *testing.T) {
	now := time.Now()
	assert.EqualValues(t, 0, timeToTimestamp(nil))
	assert.Equal(t, now.Unix(), timeToTimestamp(&now))
}
