// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauth

import (
	"context"
	"time"

	badger "github.com/outcaste-io/badger/v3"
	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"google.golang.org/protobuf/proto"

	"storj.io/gateway-mt/pkg/auth/authdb"
	"storj.io/gateway-mt/pkg/auth/badgerauth/pb"
	"storj.io/gateway-mt/pkg/backoff"
)

const (
	recordTerminatedEventName = "record_terminated"
	recordExpiredEventName    = "record_expired"
)

var (
	// Below is a compile-time check ensuring Node implements the KV interface.
	_ authdb.KV = (*Node)(nil)

	mon = monkit.Package()

	// Error is the default error class for the badgerauth package.
	Error = errs.Class("badgerauth")

	// ProtoError is a class of proto errors.
	ProtoError = errs.Class("proto")

	// ErrKeyAlreadyExists is an error returned when putting a key that exists.
	ErrKeyAlreadyExists = Error.New("key already exists")

	errOperationNotSupported           = Error.New("operation not supported")
	errKeyAlreadyExistsRecordsNotEqual = Error.New("key already exists and records aren't equal")
)

func init() {
	monkit.AddErrorNameHandler(errorName)
}

// NodeID is a unique id for BadgerDB node.
type NodeID []byte

// SetBytes sets the node id from bytes.
func (id *NodeID) SetBytes(v []byte) error {
	*id = append(NodeID{}, v...)
	return nil
}

// Bytes returns the bytes for nodeID.
func (id NodeID) Bytes() []byte { return id[:] }

type action int

const (
	put action = iota
	get
)

func (a action) String() string {
	switch a {
	case put:
		return "put"
	case get:
		return "get"
	default:
		return "unknown"
	}
}

// Node represents authservice's storage based on BadgerDB in a distributed
// environment.
type Node struct {
	db *badger.DB

	id                  NodeID
	tombstoneExpiration time.Duration
	conflictBackoff     backoff.ExponentialBackoff
}

// Config provides options for creating a Node.
type Config struct {
	ID                  NodeID
	TombstoneExpiration time.Duration
	ConflictBackoff     backoff.ExponentialBackoff
}

// New creates an instance of Node.
func New(db *badger.DB, c Config) *Node {
	return &Node{
		db:                  db,
		id:                  c.ID,
		tombstoneExpiration: c.TombstoneExpiration,
		conflictBackoff:     c.ConflictBackoff,
	}
}

// Put is like PutAtTime, but it uses current time to store the record.
func (n Node) Put(ctx context.Context, keyHash authdb.KeyHash, record *authdb.Record) error {
	return n.PutAtTime(ctx, keyHash, record, time.Now())
}

// PutAtTime stores the record at a specific time.
// It is an error if the key already exists.
func (n Node) PutAtTime(ctx context.Context, keyHash authdb.KeyHash, record *authdb.Record, now time.Time) (err error) {
	defer mon.Task(n.eventTags(put)...)(&ctx)(&err)

	// The check below is to make sure we conform to the KV interface
	// definition, and it's performed outside of the transaction because it's
	// not crucial (access key hashes are unique enough).
	if err = n.db.View(func(txn *badger.Txn) error {
		if _, err = txn.Get(keyHash[:]); err == nil {
			return ErrKeyAlreadyExists
		} else if !errs.Is(err, badger.ErrKeyNotFound) {
			return err
		}
		return nil
	}); err != nil {
		return Error.Wrap(err)
	}

	r := pb.Record{
		CreatedAtUnix:        now.Unix(),
		Public:               record.Public,
		SatelliteAddress:     record.SatelliteAddress,
		MacaroonHead:         record.MacaroonHead,
		ExpiresAtUnix:        timeToTimestamp(record.ExpiresAt),
		EncryptedSecretKey:   record.EncryptedSecretKey,
		EncryptedAccessGrant: record.EncryptedAccessGrant,
		State:                pb.Record_CREATED,
	}

	var expiresAt time.Time

	if record.ExpiresAt != nil {
		// The reason we're overwriting expiresAt with safer TTL (if necessary)
		// is because someone could insert a record with short TTL (like a few
		// seconds) that could be the last record other nodes sync. After this
		// record is deleted, all nodes would be considered out of sync.
		expiresAt = *record.ExpiresAt
		safeExpiresAt := now.Add(n.tombstoneExpiration)
		if expiresAt.Before(safeExpiresAt) {
			expiresAt = safeExpiresAt
		}
	}

	return Error.Wrap(n.txnWithBackoff(ctx, func(txn *badger.Txn) error {
		return insertRecord(txn, n.id, keyHash, &r, expiresAt)
	}))
}

// Get is like GetAtTime, but it uses current time to retrieve the record.
func (n Node) Get(ctx context.Context, keyHash authdb.KeyHash) (*authdb.Record, error) {
	return n.GetAtTime(ctx, keyHash, time.Now())
}

// GetAtTime retrieves the record from the key/value store at a specific time.
// It returns nil if the key does not exist.
// If the record is invalid, the error contains why.
func (n Node) GetAtTime(ctx context.Context, keyHash authdb.KeyHash, now time.Time) (record *authdb.Record, err error) {
	defer mon.Task(n.eventTags(get)...)(&ctx)(&err)

	return record, Error.Wrap(n.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(keyHash[:])
		if err != nil {
			if errs.Is(err, badger.ErrKeyNotFound) {
				return nil
			}
			return err
		}

		return item.Value(func(val []byte) error {
			var r pb.Record

			if err := proto.Unmarshal(val, &r); err != nil {
				return ProtoError.Wrap(err)
			}

			expiresAt := timestampToTime(r.ExpiresAtUnix)
			// The record might have expired from a logical perspective, but it
			// can have safer TTL specified (see PutAtTime), and BadgerDB will
			// still return it. We shouldn't return it in this case.
			if expiresAt != nil && expiresAt.Before(now) {
				n.monitorEvent(recordExpiredEventName, get)
				return nil
			}

			if r.InvalidationReason != "" {
				n.monitorEvent(recordTerminatedEventName, get)
				return authdb.Invalid.New("%s", r.InvalidationReason)
			}

			record = &authdb.Record{
				SatelliteAddress:     r.SatelliteAddress,
				MacaroonHead:         r.MacaroonHead,
				EncryptedSecretKey:   r.EncryptedSecretKey,
				EncryptedAccessGrant: r.EncryptedAccessGrant,
				ExpiresAt:            expiresAt,
				Public:               r.Public,
			}

			return nil
		})
	}))
}

// DeleteUnused always returns an error because expiring records are deleted by
// default.
func (n Node) DeleteUnused(context.Context, time.Duration, int, int) (int64, int64, map[string]int64, error) {
	return 0, 0, nil, Error.New("expiring records are deleted by default")
}

// Ping attempts to do a database roundtrip and returns an error if it can't.
func (n Node) Ping(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)
	// TODO(artur): what do we do here? Maybe try to retrieve a "health check"
	// record?
	return nil
}

// Close closes the underlying BadgerDB database.
func (n Node) Close() error {
	return Error.Wrap(n.db.Close())
}

func (n Node) txnWithBackoff(ctx context.Context, f func(txn *badger.Txn) error) error {
	for {
		if err := n.db.Update(f); err != nil {
			if errs.Is(err, badger.ErrConflict) && !n.conflictBackoff.Maxed() {
				if err := n.conflictBackoff.Wait(ctx); err != nil {
					return err
				}
				continue
			}
			return err
		}
		return nil
	}
}

// insertRecord inserts a record, adding a corresponding replication log entry
// consistent with the record's state. Both record and entry will get assigned
// passed expiration time if it's non-zero.
//
// insertRecord can be used to insert on any node for any node.
func insertRecord(txn *badger.Txn, nodeID NodeID, keyHash authdb.KeyHash, record *pb.Record, expiresAt time.Time) error {
	if record.State != pb.Record_CREATED {
		return errOperationNotSupported
	}
	// NOTE(artur): the check below is a sanity check (generally, this shouldn't
	// happen because access key hashes are unique) that can be slurped into the
	// replication process itself if needed.
	if i, err := txn.Get(keyHash[:]); err == nil {
		var loaded pb.Record

		if err = i.Value(func(val []byte) error {
			return proto.Unmarshal(val, &loaded)
		}); err != nil {
			return Error.Wrap(ProtoError.Wrap(err))
		}

		if uint64(expiresAt.Unix()) != i.ExpiresAt() || !recordsEqual(record, &loaded) {
			return errKeyAlreadyExistsRecordsNotEqual
		}
	} else if !errs.Is(err, badger.ErrKeyNotFound) {
		return Error.Wrap(err)
	}

	marshaled, err := proto.Marshal(record)
	if err != nil {
		return Error.Wrap(ProtoError.Wrap(err))
	}

	clock, err := advanceClock(txn, nodeID) // vector clock for this operation
	if err != nil {
		return Error.Wrap(err)
	}

	mainEntry := badger.NewEntry(keyHash[:], marshaled)
	rlogEntry := ReplicationLogEntry{
		ID:      nodeID,
		Clock:   clock,
		KeyHash: keyHash,
		State:   record.State,
	}.ToBadgerEntry()

	if !expiresAt.IsZero() {
		e := uint64(expiresAt.Unix())
		mainEntry.ExpiresAt = e
		rlogEntry.ExpiresAt = e
	}

	return Error.Wrap(errs.Combine(txn.SetEntry(mainEntry), txn.SetEntry(rlogEntry)))
}

func (n Node) eventTags(a action) []monkit.SeriesTag {
	return []monkit.SeriesTag{
		monkit.NewSeriesTag("action", a.String()),
		monkit.NewSeriesTag("node_id", string(n.id)),
	}
}

func (n Node) monitorEvent(name string, a action, tags ...monkit.SeriesTag) {
	mon.Event("as_badgerauth_"+name, n.eventTags(a)...)
}

// errorName fits the requirements for monkit.AddErrorNameHandler so that we can
// provide a useful error tag with mon.Task().
func errorName(err error) (name string, ok bool) {
	switch {
	case authdb.Invalid.Has(err):
		name = "InvalidRecord"
	case ProtoError.Has(err):
		name = "Proto"
	case ReplicationLogError.Has(err):
		// We have a wrapped error, but we want to gain more insight into
		// whether the error contains some other error we know about.
		//
		// We check ReplicationLogError first because it can contain ClockError
		// and not the other way around. TODO(artur, sean): how to make sure we
		// don't make a mistake regarding this relation in the future?
		name = "ReplicationLog"
		if unwrapped, ok := errorName(errs.Unwrap(err)); ok {
			name += ":" + unwrapped
		}
	case ClockError.Has(err):
		name = "Clock"
		if unwrapped, ok := errorName(errs.Unwrap(err)); ok {
			name += ":" + unwrapped
		}
	case errs.Is(err, ErrKeyAlreadyExists):
		name = "KeyAlreadyExists"
	case errs.Is(err, badger.ErrKeyNotFound):
		name = "KeyNotFound"
	case errs.Is(err, badger.ErrValueLogSize):
		name = "ValueLogSize"
	case errs.Is(err, badger.ErrTxnTooBig):
		name = "TxnTooBig"
	case errs.Is(err, badger.ErrConflict):
		name = "Conflict"
	case errs.Is(err, badger.ErrReadOnlyTxn):
		name = "ReadonlyTxn"
	case errs.Is(err, badger.ErrDiscardedTxn):
		name = "DiscardedTxn"
	case errs.Is(err, badger.ErrEmptyKey):
		name = "EmptyKey"
	case errs.Is(err, badger.ErrInvalidKey):
		name = "InvalidKey"
	case errs.Is(err, badger.ErrBannedKey):
		name = "BannedKey"
	case errs.Is(err, badger.ErrThresholdZero):
		name = "ThresholdZero"
	case errs.Is(err, badger.ErrNoRewrite):
		name = "NoRewrite"
	case errs.Is(err, badger.ErrRejected):
		name = "Rejected"
	case errs.Is(err, badger.ErrInvalidRequest):
		name = "InvalidRequest"
	case errs.Is(err, badger.ErrManagedTxn):
		name = "ManagedTxn"
	case errs.Is(err, badger.ErrNamespaceMode):
		name = "NamespaceMode"
	case errs.Is(err, badger.ErrInvalidDump):
		name = "InvalidDump"
	case errs.Is(err, badger.ErrZeroBandwidth):
		name = "ZeroBandwidth"
	case errs.Is(err, badger.ErrWindowsNotSupported):
		name = "WindowsNotSupported"
	case errs.Is(err, badger.ErrPlan9NotSupported):
		name = "Plan9NotSupported"
	case errs.Is(err, badger.ErrTruncateNeeded):
		name = "TruncateNeeded"
	case errs.Is(err, badger.ErrBlockedWrites):
		name = "BlockedWrites"
	case errs.Is(err, badger.ErrNilCallback):
		name = "NilCallback"
	case errs.Is(err, badger.ErrEncryptionKeyMismatch):
		name = "EncryptionKeyMismatch"
	case errs.Is(err, badger.ErrInvalidDataKeyID):
		name = "InvalidDataKeyID"
	case errs.Is(err, badger.ErrInvalidEncryptionKey):
		name = "InvalidEncryptionKey"
	case errs.Is(err, badger.ErrGCInMemoryMode):
		name = "GCInMemoryMode"
	case errs.Is(err, badger.ErrDBClosed):
		name = "DBClosed"
	}

	return name, len(name) > 0
}
