// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauth

import (
	"context"
	"sync/atomic"
	"time"

	badger "github.com/outcaste-io/badger/v3"
	"github.com/outcaste-io/badger/v3/options"
	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"storj.io/common/sync2"
	"storj.io/edge/pkg/auth/authdb"
	"storj.io/edge/pkg/auth/badgerauth/pb"
	"storj.io/edge/pkg/backoff"
)

const firstStartKey = "first_start"

var (
	_ authdb.Storage = (*DB)(nil)

	// Error is the default error class for the badgerauth package.
	Error = errs.Class("badgerauth")
	// ProtoError is a class of proto errors.
	ProtoError = errs.Class("proto")
	// ErrKeyAlreadyExists is an error returned when putting a key that exists.
	ErrKeyAlreadyExists = Error.New("key already exists")

	errOperationNotSupported = Error.New("operation not supported")
	mon                      = monkit.Package()
)

// Config provides options for creating DB.
//
// Keep this in sync with badgerauthtest.setConfigDefaults.
type Config struct {
	FirstStart bool `user:"true" help:"allow start with empty storage" devDefault:"true" releaseDefault:"false"`
	// Path is where to store data. Empty means in memory.
	Path string `user:"true" help:"path where to store data" default:""`

	// ConflictBackoff configures retries for conflicting transactions that may
	// occur when the underlying storage engine is under heavy load.
	ConflictBackoff backoff.ExponentialBackoff
}

// DB is a Storage implementation using BadgerDB.
type DB struct {
	log *zap.Logger
	db  *badger.DB

	config Config

	gcCycle    sync2.Cycle
	gcErrGroup errgroup.Group

	closed uint32
}

// Open returns initialized DB and any error encountered.
func Open(log *zap.Logger, config Config) (*DB, error) {
	if log == nil {
		return nil, Error.New("needs non-nil logger")
	}

	db := &DB{
		log:    log,
		config: config,
	}

	opt := badger.DefaultOptions(config.Path)

	if inMemory := config.Path == ""; inMemory {
		log.Warn("in-memory mode enabled. All data will be lost on shutdown!")
		opt = opt.WithInMemory(inMemory)
	}

	// We want to fsync after each write to ensure we don't lose data:
	opt = opt.WithSyncWrites(true)
	opt = opt.WithCompactL0OnClose(true)
	// Currently, we don't want to compress because authservice is mostly
	// deployed in environments where filesystem-level compression is on:
	opt = opt.WithCompression(options.None)
	// If compression and encryption are disabled, adding a cache will lead to
	// unnecessary overhead affecting read performance. Let's disable it then:
	opt = opt.WithBlockCacheSize(0)
	opt = opt.WithLogger(badgerLogger{log.Sugar().Named("storage")})

	var err error
	db.db, err = badger.Open(opt)
	if err != nil {
		return nil, Error.New("open: %w", err)
	}
	if err := db.checkFirstStart(); err != nil {
		_ = db.db.Close()
		return nil, Error.New("checkFirstStart: %w", err)
	}
	if err := db.prepare(); err != nil {
		_ = db.db.Close()
		return nil, Error.New("prepare: %w", err)
	}

	db.gcCycle.SetInterval(time.Hour)
	db.gcCycle.Start(context.TODO(), &db.gcErrGroup, db.gcValueLog)

	return db, nil
}

func (db *DB) checkFirstStart() (err error) {
	defer mon.Task()(nil)(&err)

	if db.config.FirstStart {
		return nil // first-start is toggled true, so we're safe to end here
	}

	return db.db.View(func(txn *badger.Txn) error {
		if _, err = txn.Get([]byte(firstStartKey)); errs.Is(err, badger.ErrKeyNotFound) {
			return errs.New("You've attempted to start the storage engine " +
				"with a clean storage directory (often signaling underlying " +
				"storage stopped being reliable), so we will defensively shut " +
				"down (if you know what you're doing, toggle FirstStart)")
		}
		return err
	})
}

// prepare ensures there's a value in the database.
// this allows to ensure that the database is functional.
func (db *DB) prepare() (err error) {
	defer mon.Task()(nil)(&err)

	return db.db.Update(func(txn *badger.Txn) error {
		now, err := time.Now().MarshalBinary()
		if err != nil {
			return err
		}

		item, err := txn.Get([]byte(firstStartKey))
		if err != nil {
			if errs.Is(err, badger.ErrKeyNotFound) {
				return txn.Set([]byte(firstStartKey), now)
			}
			return err
		}

		return item.Value(func(val []byte) error {
			var t time.Time
			if err := t.UnmarshalBinary(val); err != nil {
				return errs.New("initialization went wrong: %w", err)
			}
			return nil
		})
	})
}

// gcValueLog garbage collects value log. It always returns a nil error.
func (db *DB) gcValueLog(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(nil)

gcLoop:
	for err == nil {
		gcFinished := mon.TaskNamed("gc")(&ctx)
		select {
		case <-ctx.Done():
			err = ctx.Err()
		default:
			// Run GC and optionally silence ErrNoRewrite errors:
			if err = db.db.RunValueLogGC(.5); errs.Is(err, badger.ErrNoRewrite) {
				gcFinished(nil)
				err = nil
				break gcLoop
			}
		}
		gcFinished(&err)
	}
	db.log.Info("value log garbage collection finished", zap.Error(err))
	return nil
}

func (db *DB) txnWithBackoff(ctx context.Context, f func(txn *badger.Txn) error) error {
	// db.config.ConflictBackoff needs to be copied. Otherwise, we are using one
	// for all queries.
	conflictBackoff := db.config.ConflictBackoff
	for {
		if err := db.db.Update(f); err != nil {
			if errs.Is(err, badger.ErrConflict) && !conflictBackoff.Maxed() {
				mon.Event("as_badgerauth_txn_backoff")
				if err := conflictBackoff.Wait(ctx); err != nil {
					return err
				}
				continue
			}
			return err
		}
		return nil
	}
}

// Put is like PutAtTime, but it uses current time to store the record.
func (db *DB) Put(ctx context.Context, keyHash authdb.KeyHash, record *authdb.Record) error {
	return db.PutAtTime(ctx, keyHash, record, time.Now())
}

// PutAtTime stores the record at a specific time.
// It is an error if the key already exists.
func (db *DB) PutAtTime(ctx context.Context, keyHash authdb.KeyHash, record *authdb.Record, now time.Time) (err error) {
	defer mon.Task()(&ctx)(&err)

	r := pb.Record{
		CreatedAtUnix:        now.Unix(),
		Public:               record.Public,
		SatelliteAddress:     record.SatelliteAddress,
		PublicProjectId:      record.PublicProjectID,
		MacaroonHead:         record.MacaroonHead,
		ExpiresAtUnix:        timeToTimestamp(record.ExpiresAt),
		EncryptedSecretKey:   record.EncryptedSecretKey,
		EncryptedAccessGrant: record.EncryptedAccessGrant,
		State:                pb.Record_CREATED,
		UsageTags:            record.UsageTags,
	}

	return Error.Wrap(db.txnWithBackoff(ctx, func(txn *badger.Txn) error {
		return insertRecord(txn, keyHash, &r)
	}))
}

// Get retrieves the record from the storage engine. It returns nil if the key
// does not exist. If the record is invalid, the error contains why.
func (db *DB) Get(ctx context.Context, keyHash authdb.KeyHash) (record *authdb.Record, err error) {
	defer mon.Task()(&ctx)(&err)

	return record, Error.Wrap(db.db.View(func(txn *badger.Txn) error {
		r, err := lookupRecordWithTxn(txn, keyHash)
		if err != nil {
			if errs.Is(err, badger.ErrKeyNotFound) {
				return nil
			}
			return err
		}

		if r.InvalidationReason != "" {
			mon.Event("as_badgerauth_record_terminated")
			return authdb.Invalid.New("%s", r.InvalidationReason)
		}

		record = &authdb.Record{
			SatelliteAddress:     r.SatelliteAddress,
			PublicProjectID:      r.PublicProjectId,
			MacaroonHead:         r.MacaroonHead,
			EncryptedSecretKey:   r.EncryptedSecretKey,
			EncryptedAccessGrant: r.EncryptedAccessGrant,
			ExpiresAt:            timestampToTime(r.ExpiresAtUnix),
			Public:               r.Public,
			UsageTags:            r.UsageTags,
		}

		return nil
	}))
}

// HealthCheck ensures the underlying storage engine works and returns an error
// otherwise.
func (db *DB) HealthCheck(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	err = db.db.View(func(txn *badger.Txn) error {
		_, err := txn.Get([]byte(firstStartKey))
		return err
	})
	if err != nil {
		return Error.New("unable to read start time: %w", err)
	}

	// TODO(artur): is this the best place to report these?
	// TODO(artur): we can also report information from Levels() or Tables() or
	// cache's metrics.
	lsm, vlog := db.db.Size()
	mon.IntVal("as_badgerauth_kv_bytes_lsm").Observe(lsm)
	mon.IntVal("as_badgerauth_kv_bytes_vlog").Observe(vlog)

	return nil
}

// Close closes the underlying storage engine (BadgerDB).
func (db *DB) Close() error {
	if !atomic.CompareAndSwapUint32(&db.closed, 0, 1) {
		return nil
	}
	db.gcCycle.Close()
	return Error.Wrap(errs.Combine(db.gcErrGroup.Wait(), db.db.Close()))
}

// insertRecord inserts a record.
func insertRecord(txn *badger.Txn, keyHash authdb.KeyHash, record *pb.Record) error {
	if record.State != pb.Record_CREATED {
		return errOperationNotSupported
	}

	if _, err := txn.Get(keyHash.Bytes()); err == nil {
		mon.Event("as_badgerauth_duplicate_key")
		return ErrKeyAlreadyExists
	} else if !errs.Is(err, badger.ErrKeyNotFound) {
		return err
	}

	marshaled, err := pb.Marshal(record)
	if err != nil {
		return ProtoError.Wrap(err)
	}

	entry := badger.NewEntry(keyHash.Bytes(), marshaled)

	if record.ExpiresAtUnix > 0 {
		// TODO(artur): maybe it would be good to report buckets given TTL would
		// fall into (for later analysis).
		mon.Event("as_badgerauth_expiring_insert")
		entry.ExpiresAt = uint64(record.ExpiresAtUnix)
	} else {
		mon.Event("as_badgerauth_insert")
	}

	return txn.SetEntry(entry)
}

func lookupRecordWithTxn(txn *badger.Txn, keyHash authdb.KeyHash) (*pb.Record, error) {
	var record pb.Record

	item, err := txn.Get(keyHash.Bytes())
	if err != nil {
		return nil, err
	}

	return &record, item.Value(func(val []byte) error {
		return ProtoError.Wrap(pb.Unmarshal(val, &record))
	})
}
