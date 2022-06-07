// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauth

import (
	"encoding/binary"

	badger "github.com/outcaste-io/badger/v3"
	"github.com/zeebo/errs"

	"storj.io/gateway-mt/pkg/auth/authdb"
	"storj.io/gateway-mt/pkg/auth/badgerauth/pb"
)

const (
	replicationLogPrefix    = "replication_log" + replicationLogEntrySeparator
	lenReplicationLogPrefix = len(replicationLogPrefix)

	replicationLogEntrySeparator    = "/"
	lenReplicationLogEntrySeparator = len(replicationLogEntrySeparator)

	lenNodeID  = len(NodeID{})
	lenKeyHash = len(authdb.KeyHash{})

	lenReplicationLogEntry = lenReplicationLogPrefix + 3*lenReplicationLogEntrySeparator + lenNodeID + lenKeyHash + 8 + 4
)

// ReplicationLogError is a class of replication log errors.
var ReplicationLogError = errs.Class("replication log")

// ReplicationLogEntry represents replication log entry.
//
// Key layout reference:
// https://github.com/storj/gateway-mt/blob/3ef75f412a50118d9d910e1b372e126e6ffb7503/docs/blueprints/new-auth-database.md#replication-log-entry
type ReplicationLogEntry struct {
	ID      NodeID
	Clock   Clock
	KeyHash authdb.KeyHash
	State   pb.Record_State
}

// Bytes returns a slice of bytes.
func (e ReplicationLogEntry) Bytes() []byte {
	var stateBytes [4]byte
	binary.BigEndian.PutUint32(stateBytes[:], uint32(e.State))

	key := make([]byte, 0, lenReplicationLogEntry)
	key = append(key, replicationLogPrefix...)
	key = append(key, e.ID.Bytes()...)
	key = append(key, replicationLogEntrySeparator...)
	key = append(key, e.Clock.Bytes()...)
	key = append(key, replicationLogEntrySeparator...)
	key = append(key, e.KeyHash.Bytes()...)
	key = append(key, replicationLogEntrySeparator...)
	key = append(key, stateBytes[:]...)

	return key
}

// ToBadgerEntry constructs new *badger.Entry from e.
func (e ReplicationLogEntry) ToBadgerEntry() *badger.Entry {
	return badger.NewEntry(e.Bytes(), nil)
}

// SetBytes parses entry as ReplicationLogEntry and sets entry's value to result.
func (e *ReplicationLogEntry) SetBytes(entry []byte) error {
	// Make sure we don't keep a reference to the input entry.
	entry = append([]byte{}, entry...)

	if len(entry) != lenReplicationLogEntry {
		return ReplicationLogError.New("incorrect entry length")
	}

	entry = entry[lenReplicationLogPrefix:] // trim leftmost replicationLogPrefix
	idBytes, entry := entry[:lenNodeID], entry[lenNodeID:]
	entry = entry[lenReplicationLogEntrySeparator:] // trim leftmost separator
	clockBytes, entry := entry[:8], entry[8:]
	entry = entry[lenReplicationLogEntrySeparator:] // trim leftmost separator
	keyHash, entry := entry[:lenKeyHash], entry[lenKeyHash:]
	entry = entry[lenReplicationLogEntrySeparator:] // trim leftmost separator
	stateBytes := entry                             // the state is the remainder

	if err := e.Clock.SetBytes(clockBytes); err != nil {
		return ReplicationLogError.Wrap(err)
	}

	if err := e.ID.SetBytes(idBytes); err != nil {
		return ReplicationLogError.Wrap(err)
	}

	e.KeyHash = *(*[32]byte)(keyHash)
	e.State = pb.Record_State(binary.BigEndian.Uint32(stateBytes))

	return nil
}

func makeIterationStartKey(id NodeID, clock Clock) []byte {
	p := make([]byte, 0, lenReplicationLogPrefix+lenNodeID+lenReplicationLogEntrySeparator+8)
	p = append(p, replicationLogPrefix...)
	p = append(p, id.Bytes()...)
	p = append(p, replicationLogEntrySeparator...)
	p = append(p, clock.Bytes()...)
	return p
}
