// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauth

import (
	"encoding/binary"

	badger "github.com/outcaste-io/badger/v3"
	"github.com/zeebo/errs"
)

// Clock represents logical time on a single Node.
type Clock uint64

// SetBytes parses []byte for the clock value.
func (clock *Clock) SetBytes(v []byte) error {
	if len(v) != 8 {
		return Error.New("invalid clock length: %v", len(v))
	}
	*clock = Clock(binary.BigEndian.Uint64(v))
	return nil
}

// Bytes returns a slice of bytes.
func (clock Clock) Bytes() []byte {
	var r [8]byte
	binary.BigEndian.PutUint64(r[:], uint64(clock))
	return r[:]
}

// ReadClock reads the current clock value for the node.
func ReadClock(txn *badger.Txn, id NodeID) (Clock, error) {
	item, err := txn.Get(makeClockKey(id))
	if err != nil {
		return 0, Error.Wrap(err)
	}

	var current Clock
	err = item.Value(current.SetBytes)
	return current, Error.Wrap(err)
}

// makeClockKey creates a badgerDB key for reading clock value
// for the specified node.
func makeClockKey(id NodeID) []byte {
	return append([]byte("clock_value/"), id.Bytes()...)
}

// advanceClock advances the current clock value for the node.
func advanceClock(txn *badger.Txn, id NodeID) (next Clock, _ error) {
	key := makeClockKey(id)

	var current Clock

	item, err := txn.Get(key)
	if err != nil && !errs.Is(err, badger.ErrKeyNotFound) {
		return 0, err
	} else if err == nil {
		if err = item.Value(current.SetBytes); err != nil {
			return 0, Error.Wrap(err)
		}
	}

	current++
	return current, txn.Set(key, current.Bytes())
}
