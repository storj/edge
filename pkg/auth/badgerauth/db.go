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
)

const (
	recordTerminatedEventName = "record_terminated"
	recordExpiredEventName    = "record_expired"
	startTimeEntryKey         = "start_time"
)

var (
	// Below is a compile-time check ensuring DB implements the KV interface.
	_ authdb.KV = (*DB)(nil)

	// ProtoError is a class of proto errors.
	ProtoError = errs.Class("proto")

	// ErrKeyAlreadyExists is an error returned when putting a key that exists.
	ErrKeyAlreadyExists = Error.New("key already exists")

	errOperationNotSupported           = Error.New("operation not supported")
	errKeyAlreadyExistsRecordsNotEqual = Error.New("key already exists and records aren't equal")
)

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

// DB represents authentication storage based on BadgerDB.
// This implements the data-storage layer for a distributed
// Node.
type DB struct {
	db *badger.DB

	config Config
}

// New creates an instance of DB.
func New(db *badger.DB, config Config) (*DB, error) {
	ndb := &DB{
		db:     db,
		config: config,
	}
	return ndb, ndb.prepare()
}

// prepare ensures there's a value in the database.
// this allows to ensure that the database is functional.
func (db *DB) prepare() (err error) {
	defer mon.Task(db.eventTags(put)...)(nil)(&err)
	err = db.db.Update(func(txn *badger.Txn) error {
		now := time.Now()
		text := now.Format(time.RFC3339)
		err := txn.Set([]byte(startTimeEntryKey), []byte(text))
		return Error.Wrap(err)
	})
	return Error.Wrap(err)
}

// Close closes the underlying BadgerDB database.
func (db *DB) Close() error {
	return Error.Wrap(db.db.Close())
}

// Put is like PutAtTime, but it uses current time to store the record.
func (db *DB) Put(ctx context.Context, keyHash authdb.KeyHash, record *authdb.Record) error {
	return db.PutAtTime(ctx, keyHash, record, time.Now())
}

// PutAtTime stores the record at a specific time.
// It is an error if the key already exists.
func (db *DB) PutAtTime(ctx context.Context, keyHash authdb.KeyHash, record *authdb.Record, now time.Time) (err error) {
	defer mon.Task(db.eventTags(put)...)(&ctx)(&err)

	// The check below is to make sure we conform to the KV interface
	// definition, and it's performed outside of the transaction because it's
	// not crucial (access key hashes are unique enough).
	if err = db.db.View(func(txn *badger.Txn) error {
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
		safeExpiresAt := now.Add(db.config.TombstoneExpiration)
		if expiresAt.Before(safeExpiresAt) {
			expiresAt = safeExpiresAt
		}
	}

	return Error.Wrap(db.txnWithBackoff(ctx, func(txn *badger.Txn) error {
		return insertRecord(txn, db.config.ID, keyHash, &r, expiresAt)
	}))
}

// Get is like GetAtTime, but it uses current time to retrieve the record.
func (db *DB) Get(ctx context.Context, keyHash authdb.KeyHash) (*authdb.Record, error) {
	return db.GetAtTime(ctx, keyHash, time.Now())
}

// GetAtTime retrieves the record from the key/value store at a specific time.
// It returns nil if the key does not exist.
// If the record is invalid, the error contains why.
func (db *DB) GetAtTime(ctx context.Context, keyHash authdb.KeyHash, now time.Time) (record *authdb.Record, err error) {
	defer mon.Task(db.eventTags(get)...)(&ctx)(&err)

	return record, Error.Wrap(db.db.View(func(txn *badger.Txn) error {
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
				db.monitorEvent(recordExpiredEventName, get)
				return nil
			}

			if r.InvalidationReason != "" {
				db.monitorEvent(recordTerminatedEventName, get)
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
func (db *DB) DeleteUnused(context.Context, time.Duration, int, int) (int64, int64, map[string]int64, error) {
	return 0, 0, nil, Error.New("expiring records are deleted by default")
}

// Ping attempts to do a database roundtrip and returns an error if it can't.
func (db *DB) Ping(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	err = db.db.View(func(txn *badger.Txn) error {
		_, err := txn.Get([]byte(startTimeEntryKey))
		return err
	})
	if err != nil {
		return Error.New("unable to read start time: %w", err)
	}

	return nil
}

func (db *DB) txnWithBackoff(ctx context.Context, f func(txn *badger.Txn) error) error {
	for {
		if err := db.db.Update(f); err != nil {
			if errs.Is(err, badger.ErrConflict) && !db.config.ConflictBackoff.Maxed() {
				if err := db.config.ConflictBackoff.Wait(ctx); err != nil {
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

func (db *DB) eventTags(a action) []monkit.SeriesTag {
	return []monkit.SeriesTag{
		monkit.NewSeriesTag("action", a.String()),
		monkit.NewSeriesTag("node_id", string(db.config.ID)),
	}
}

func (db *DB) monitorEvent(name string, a action, tags ...monkit.SeriesTag) {
	mon.Event("as_badgerauth_"+name, db.eventTags(a)...)
}
