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

	"storj.io/common/testrand"
	"storj.io/gateway-mt/pkg/auth/authdb"
	"storj.io/gateway-mt/pkg/auth/badgerauth/pb"
)

var mon = monkit.Package()

// Error is the default error class for the badgerauth package.
var Error = errs.Class("badgerauth")

// Below is a compile-time check ensuring Node implements the KV interface.
var _ authdb.KV = (*Node)(nil)

// Node represents authservice's storage based on BadgerDB in a distributed
// environment.
type Node struct {
	db *badger.DB

	id                  []byte
	tombstoneExpiration time.Duration
}

// Put is like PutAtTime, but it uses current time to store the record.
func (n Node) Put(ctx context.Context, keyHash authdb.KeyHash, record *authdb.Record) error {
	return n.PutAtTime(ctx, keyHash, record, time.Now())
}

// PutAtTime stores the record at a specific time.
// It is an error if the key already exists.
func (n Node) PutAtTime(ctx context.Context, keyHash authdb.KeyHash, record *authdb.Record, now time.Time) (err error) {
	defer mon.Task()(&ctx)(&err)

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
	marshaled, err := proto.Marshal(&r)
	if err != nil {
		return Error.Wrap(err)
	}

	if err = n.db.View(func(txn *badger.Txn) error {
		if _, err = txn.Get(keyHash[:]); err == nil {
			return errs.New("key already exists")
		} else if !errs.Is(err, badger.ErrKeyNotFound) {
			return err
		}
		return nil
	}); err != nil {
		return Error.Wrap(err)
	}

	return Error.Wrap(n.db.Update(func(txn *badger.Txn) error {
		clockValue, err := nextClockValue(txn, n.id) // vector clock for this operation
		if err != nil {
			return err
		}

		mainEntry := badger.NewEntry(keyHash[:], marshaled)
		rlogEntry := newReplicationLogEntry(n.id, clockValue, keyHash, pb.Record_CREATED)
		if record.ExpiresAt != nil {
			// The reason we're overwriting expiresAt with safer TTL (if
			// necessary) is because someone could insert a record with short
			// TTL (like a few seconds) that could be the last record other
			// nodes sync. After this record is deleted, all nodes would be
			// considered out of sync.
			expiresAt := uint64(record.ExpiresAt.Unix())
			safeExpiresAt := now.Add(n.tombstoneExpiration)
			if record.ExpiresAt.Before(safeExpiresAt) {
				expiresAt = uint64(safeExpiresAt.Unix())
			}
			mainEntry.ExpiresAt = expiresAt
			rlogEntry.ExpiresAt = expiresAt
		}

		return errs.Combine(txn.SetEntry(mainEntry), txn.SetEntry(rlogEntry))
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
	defer mon.Task()(&ctx)(&err)

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
				return err
			}

			expiresAt := timestampToTime(r.ExpiresAtUnix)
			// The record might have expired from a logical perspective, but it
			// can have safer TTL specified (see PutAtTime), and BadgerDB will
			// still return it. We shouldn't return it in this case.
			if expiresAt != nil && expiresAt.Before(now) {
				return nil
			}

			switch r.State {
			case pb.Record_INVALIDATED:
				return authdb.Invalid.New("%s", r.InvalidationReason)
			case pb.Record_DELETED:
				// We encountered the record's tombstone. It's gone from the
				// user's perspective.
				return nil
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

// Delete is like DeleteAtTime, but it uses the current time to remove the
// record.
func (n Node) Delete(ctx context.Context, keyHash authdb.KeyHash) error {
	return n.DeleteAtTime(ctx, keyHash, time.Now())
}

// DeleteAtTime removes the record at a specific time.
// It is not an error if the key does not exist.
func (n Node) DeleteAtTime(ctx context.Context, keyHash authdb.KeyHash, now time.Time) (err error) {
	defer mon.Task()(&ctx)(&err)

	return Error.Wrap(n.db.Update(func(txn *badger.Txn) error {
		item, err := txn.Get(keyHash[:])
		if err != nil {
			if errs.Is(err, badger.ErrKeyNotFound) {
				return nil
			}
			return err
		}

		var record pb.Record

		if err = item.Value(func(val []byte) error {
			return proto.Unmarshal(val, &record)
		}); err != nil {
			return err
		}

		if record.State == pb.Record_DELETED {
			return nil // nothing to do here
		}

		// The record might have expired from a logical perspective, but it can
		// have safer TTL specified (see PutAtTime), and BadgerDB will still
		// return it. We shouldn't process it in this case.
		if t := timestampToTime(record.ExpiresAtUnix); t != nil && t.Before(now) {
			return nil
		}

		record.State = pb.Record_DELETED

		marshaled, err := proto.Marshal(&record)
		if err != nil {
			return err
		}
		clockValue, err := nextClockValue(txn, n.id) // vector clock for this operation
		if err != nil {
			return err
		}

		expiresAt := uint64(now.Add(n.tombstoneExpiration).Unix())
		mainEntry := badger.NewEntry(keyHash[:], marshaled)
		rlogEntry := newReplicationLogEntry(n.id, clockValue, keyHash, pb.Record_DELETED)
		mainEntry.ExpiresAt = expiresAt
		rlogEntry.ExpiresAt = expiresAt

		var errors []error
		// We have to re-add entries for keyHash with tombstoneExpiration as
		// they also need to be deleted, like the main entry, after this period.
		for _, entry := range findReplicationLogEntriesByKeyHash(txn, keyHash) {
			e := badger.NewEntry(entry, nil)
			e.ExpiresAt = expiresAt
			errors = append(errors, txn.SetEntry(e))
		}
		errors = append(errors, txn.SetEntry(mainEntry))
		errors = append(errors, txn.SetEntry(rlogEntry))

		return errs.Combine(errors...)
	}))
}

// DeleteUnused always returns an error because expiring records are deleted by
// default.
func (n Node) DeleteUnused(context.Context, time.Duration, int, int) (int64, int64, map[string]int64, error) {
	return 0, 0, nil, Error.New("expiring records are deleted by default")
}

// Invalidate is like InvalidateAtTime, but it uses current time to invalidate
// the record.
func (n Node) Invalidate(ctx context.Context, keyHash authdb.KeyHash, reason string) error {
	return n.InvalidateAtTime(ctx, keyHash, reason, time.Now())
}

// InvalidateAtTime causes the record to become invalid.
// It is not an error if the key does not exist.
// It does not update the invalid reason if the record is already invalid.
func (n Node) InvalidateAtTime(ctx context.Context, keyHash authdb.KeyHash, reason string, now time.Time) (err error) {
	defer mon.Task()(&ctx)(&err)

	return Error.Wrap(n.db.Update(func(txn *badger.Txn) error {
		item, err := txn.Get(keyHash[:])
		if err != nil {
			if errs.Is(err, badger.ErrKeyNotFound) {
				return nil
			}
			return err
		}

		var record pb.Record

		if err = item.Value(func(val []byte) error {
			return proto.Unmarshal(val, &record)
		}); err != nil {
			return err
		}

		if record.State == pb.Record_INVALIDATED || record.State == pb.Record_DELETED {
			return nil // nothing to do here
		}

		// The record might have expired from a logical perspective, but it can
		// have safer TTL specified (see PutAtTime), and BadgerDB will still
		// return it. We shouldn't process it in this case.
		if t := timestampToTime(record.ExpiresAtUnix); t != nil && t.Before(now) {
			return nil
		}

		record.InvalidationReason, record.InvalidatedAtUnix = reason, now.Unix()
		record.State = pb.Record_INVALIDATED

		marshaled, err := proto.Marshal(&record)
		if err != nil {
			return err
		}
		clockValue, err := nextClockValue(txn, n.id) // vector clock for this operation
		if err != nil {
			return err
		}

		mainEntry := badger.NewEntry(keyHash[:], marshaled)
		rlogEntry := newReplicationLogEntry(n.id, clockValue, keyHash, pb.Record_INVALIDATED)
		mainEntry.ExpiresAt = item.ExpiresAt()
		rlogEntry.ExpiresAt = item.ExpiresAt()

		return errs.Combine(
			txn.SetEntry(mainEntry),
			txn.SetEntry(rlogEntry),
		)
	}))
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

// NewTestNode creates an instance of Node suitable for testing by wrapping
// around the passed db.
func NewTestNode(db *badger.DB, tombstoneExpiration time.Duration) *Node {
	return &Node{
		db:                  db,
		id:                  testrand.UUID().Bytes(),
		tombstoneExpiration: tombstoneExpiration,
	}
}
