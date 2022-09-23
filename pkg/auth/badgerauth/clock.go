// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauth

import (
	"encoding/binary"

	badger "github.com/outcaste-io/badger/v3"
	"github.com/zeebo/errs"
)

// ClockError is a class of clock errors.
var ClockError = errs.Class("clock")

const clockPrefix = "clock_value/"

// Clock represents logical time on a single DB.
type Clock uint64

// SetBytes parses []byte for the clock value.
func (clock *Clock) SetBytes(v []byte) error {
	if len(v) != 8 {
		return ClockError.New("invalid length: %v", len(v))
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
		return 0, ClockError.Wrap(err)
	}

	var current Clock
	err = item.Value(current.SetBytes)
	return current, ClockError.Wrap(err)
}

// makeClockKey creates a badgerDB key for reading clock value
// for the specified node.
func makeClockKey(id NodeID) []byte {
	return append([]byte(clockPrefix), id.Bytes()...)
}

// advanceClock advances the current clock value for the node.
func advanceClock(txn *badger.Txn, id NodeID) (next Clock, _ error) {
	key := makeClockKey(id)

	var current Clock

	item, err := txn.Get(key)
	if err != nil && !errs.Is(err, badger.ErrKeyNotFound) {
		return 0, ClockError.Wrap(err)
	} else if err == nil {
		if err = item.Value(current.SetBytes); err != nil {
			return 0, ClockError.Wrap(err)
		}
	}

	current++
	return current, ClockError.Wrap(txn.Set(key, current.Bytes()))
}

func ensureClock(txn *badger.Txn, id NodeID) error {
	key := makeClockKey(id)

	_, err := txn.Get(key)
	if err != nil && !errs.Is(err, badger.ErrKeyNotFound) {
		return ClockError.Wrap(err)
	} else if errs.Is(err, badger.ErrKeyNotFound) {
		return ClockError.Wrap(txn.Set(key, Clock.Bytes(0)))
	}

	return nil
}

func readAvailableClocks(txn *badger.Txn) (map[NodeID]Clock, error) {
	idToClock := make(map[NodeID]Clock)

	opt := badger.DefaultIteratorOptions
	// It's much faster without prefetching values, probably because we discard
	// a lot of them anyway.
	opt.PrefetchValues = false
	opt.Prefix = []byte(clockPrefix)

	it := txn.NewIterator(opt)
	defer it.Close()

	for it.Rewind(); it.Valid(); it.Next() {
		var (
			id    NodeID
			clock Clock
		)

		item := it.Item()

		if err := id.SetBytes(item.Key()[len(clockPrefix):]); err != nil {
			return nil, ClockError.Wrap(err)
		}
		if err := item.Value(clock.SetBytes); err != nil {
			return nil, ClockError.Wrap(err)
		}

		idToClock[id] = clock
	}

	return idToClock, nil
}
