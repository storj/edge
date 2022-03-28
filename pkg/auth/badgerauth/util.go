// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauth

import (
	"encoding/binary"
	"time"

	badger "github.com/outcaste-io/badger/v3"
	"go.uber.org/zap"

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
func newReplicationLogEntry(id NodeID, clock Clock, keyHash authdb.KeyHash, state pb.Record_State) *badger.Entry {
	var stateBytes [4]byte
	binary.BigEndian.PutUint32(stateBytes[:], uint32(state))

	key := make([]byte, 0, lenReplicationLogPrefix+3*lenReplicationLogSeparator+len(id)+lenKeyHash+8+4)
	key = append(key, replicationLogPrefix...)
	key = append(key, id.Bytes()...)
	key = append(key, replicationLogSeparator...)
	key = append(key, clock.Bytes()...)
	key = append(key, replicationLogSeparator...)
	key = append(key, keyHash[:]...)
	key = append(key, replicationLogSeparator...)
	key = append(key, stateBytes[:]...)

	return badger.NewEntry(key, nil)
}

func parseReplicationLogEntry(entry []byte) (NodeID, Clock, authdb.KeyHash, pb.Record_State) {
	entry = entry[lenReplicationLogPrefix:] // trim leftmost replicationLogPrefix
	stateBytes, entry := entry[len(entry)-4:], entry[:len(entry)-4]
	entry = entry[:len(entry)-lenReplicationLogSeparator] // trim rightmost separator
	keyHash, entry := entry[len(entry)-lenKeyHash:], entry[:len(entry)-lenKeyHash]
	entry = entry[:len(entry)-lenReplicationLogSeparator] // trim rightmost separator
	clockBytes, entry := entry[len(entry)-8:], entry[:len(entry)-8]
	entry = entry[:len(entry)-lenReplicationLogSeparator] // trim rightmost separator
	idBytes := entry                                      // ID is the remainder

	var clock Clock
	if err := clock.SetBytes(clockBytes); err != nil {
		panic(err)
	}

	var id NodeID
	if err := id.SetBytes(idBytes); err != nil {
		panic(err)
	}

	state := pb.Record_State(binary.BigEndian.Uint32(stateBytes))

	return id, clock, *(*[32]byte)(keyHash), state
}

func findReplicationLogEntriesByKeyHash(txn *badger.Txn, keyHash authdb.KeyHash) [][]byte {
	var entries [][]byte

	opt := badger.DefaultIteratorOptions      // TODO(artur): should we also set SinceTs?
	opt.PrefetchValues = false                // fasten your seatbelts; see: https://dgraph.io/docs/badger/get-started/#key-only-iteration
	opt.Prefix = []byte(replicationLogPrefix) // don't roll through everything

	it := txn.NewIterator(opt)
	defer it.Close()
	for it.Rewind(); it.Valid(); it.Next() {
		if _, _, k, _ := parseReplicationLogEntry(it.Item().Key()); k == keyHash {
			// We need to call KeyCopy because the underlying slice of bytes is
			// only valid in this iteration.
			//
			// As an optimization, we copy it only when we are sure we need it.
			entries = append(entries, it.Item().KeyCopy(nil))
		}
	}

	return entries
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

// Logger wraps zap's SugaredLogger, so it's possible to use it as badger's
// Logger.
type Logger struct {
	*zap.SugaredLogger
}

// Warningf wraps zap's Warnf.
func (l Logger) Warningf(format string, v ...interface{}) {
	l.Warnf(format, v)
}

// NewLogger returns new Logger.
func NewLogger(s *zap.SugaredLogger) Logger {
	return Logger{s.Named("BadgerDB")}
}
