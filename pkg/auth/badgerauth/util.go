// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauth

import (
	"encoding/binary"
	"time"

	badger "github.com/outcaste-io/badger/v3"
	"github.com/zeebo/errs"

	"storj.io/gateway-mt/pkg/auth/authdb"
	"storj.io/gateway-mt/pkg/auth/badgerauth/pb"
)

const (
	replicationLogSeparator    = "/"
	replicationLogPrefix       = "replication_log" + replicationLogSeparator
	lenReplicationLogSeparator = len(replicationLogSeparator)
	lenReplicationLogPrefix    = len(replicationLogPrefix)
	lenKeyHash                 = len(authdb.KeyHash{})
)

// newReplicationLogEntry constructs new *badger.Entry for replication log.
//
// Key layout reference:
// https://github.com/storj/gateway-mt/blob/3ef75f412a50118d9d910e1b372e126e6ffb7503/docs/blueprints/new-auth-database.md#replication-log-entry
func newReplicationLogEntry(id []byte, clockValue uint64, keyHash authdb.KeyHash, state pb.Record_State) *badger.Entry {
	var (
		clockValueBytes [8]byte
		stateBytes      [4]byte
	)
	binary.BigEndian.PutUint64(clockValueBytes[:], clockValue)
	binary.BigEndian.PutUint32(stateBytes[:], uint32(state))

	key := make([]byte, 0, lenReplicationLogPrefix+3*lenReplicationLogSeparator+len(id)+lenKeyHash+8+4)
	key = append(key, replicationLogPrefix...)
	key = append(key, id...)
	key = append(key, replicationLogSeparator...)
	key = append(key, clockValueBytes[:]...)
	key = append(key, replicationLogSeparator...)
	key = append(key, keyHash[:]...)
	key = append(key, replicationLogSeparator...)
	key = append(key, stateBytes[:]...)

	return badger.NewEntry(key, nil)
}

func parseReplicationLogEntry(entry []byte) ([]byte, uint64, authdb.KeyHash, pb.Record_State) {
	entry = entry[lenReplicationLogPrefix:] // trim leftmost replicationLogPrefix
	stateBytes, entry := entry[len(entry)-4:], entry[:len(entry)-4]
	entry = entry[:len(entry)-lenReplicationLogSeparator] // trim rightmost separator
	keyHash, entry := entry[len(entry)-lenKeyHash:], entry[:len(entry)-lenKeyHash]
	entry = entry[:len(entry)-lenReplicationLogSeparator] // trim rightmost separator
	clockValueBytes, entry := entry[len(entry)-8:], entry[:len(entry)-8]
	entry = entry[:len(entry)-lenReplicationLogSeparator] // trim rightmost separator
	id := entry                                           // ID is the remainder

	clockValue := binary.BigEndian.Uint64(clockValueBytes)
	state := pb.Record_State(binary.BigEndian.Uint32(stateBytes))

	return id, clockValue, *(*[32]byte)(keyHash), state
}

func findReplicationLogEntriesByKeyHash(txn *badger.Txn, keyHash authdb.KeyHash) [][]byte {
	var entries [][]byte

	opt := badger.DefaultIteratorOptions      // TODO(artur): should we also set SinceTs?
	opt.PrefetchValues = false                // fasten your seatbelts; see: https://dgraph.io/docs/badger/get-started/#key-only-iteration
	opt.Prefix = []byte(replicationLogPrefix) // don't roll through everything

	it := txn.NewIterator(opt)
	defer it.Close()
	for it.Rewind(); it.Valid(); it.Next() {
		entry := it.Item().Key()
		if _, _, k, _ := parseReplicationLogEntry(entry); k == keyHash {
			entries = append(entries, entry)
		}
	}

	return entries
}

func nextClockValue(txn *badger.Txn, id []byte) (uint64, error) {
	key := makeClockValueKey(id)

	var current uint64

	item, err := txn.Get(key)
	if err != nil && !errs.Is(err, badger.ErrKeyNotFound) {
		return 0, err
	} else if err == nil {
		if err = item.Value(func(v []byte) error {
			current = binary.BigEndian.Uint64(v)
			return nil
		}); err != nil {
			return 0, err
		}
	}

	current++

	var b [8]byte
	binary.BigEndian.PutUint64(b[:], current)
	return current, txn.Set(key, b[:])
}

//lint:ignore U1000, it will be used for #123
//nolint: deadcode
func readClockValue(txn *badger.Txn, id []byte) (uint64, error) {
	item, err := txn.Get(makeClockValueKey(id))
	if err != nil {
		return 0, err
	}

	var current uint64
	err = item.Value(func(v []byte) error {
		current = binary.BigEndian.Uint64(v)
		return nil
	})

	return current, err
}

func makeClockValueKey(id []byte) []byte {
	return append([]byte("clock_value/"), id...)
}

// timestampToTime converts Unix time to *time.Time. It checks whether the
// supplied number of seconds is greater than 0 and returns nil *time.Time
// otherwise.
func timestampToTime(sec int64) *time.Time {
	if sec > 0 {
		t := time.Unix(sec, 0)
		return &t
	}
	return nil
}

// timeToTimestamp converts t to Unix time. It returns 0 if t is nil.
func timeToTimestamp(t *time.Time) int64 {
	if t != nil {
		return t.Unix()
	}
	return 0
}
