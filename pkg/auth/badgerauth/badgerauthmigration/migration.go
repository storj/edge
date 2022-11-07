// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

// Package badgerauthmigration helps move to badgerauth from sqlauth.
package badgerauthmigration

import (
	"context"
	"time"

	badger "github.com/outcaste-io/badger/v3"
	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"storj.io/gateway-mt/pkg/auth/authdb"
	"storj.io/gateway-mt/pkg/auth/badgerauth"
	"storj.io/gateway-mt/pkg/auth/badgerauth/pb"
	"storj.io/gateway-mt/pkg/auth/sqlauth"
	"storj.io/gateway-mt/pkg/auth/sqlauth/dbx"
)

// Error is the default error class for the badgerauthmigration package.
var Error = errs.Class("badgerauthmigration")

// Config represents config for KV.
type Config struct {
	MigrationSelectSize    int    `user:"true" help:"page size while performing migration"                 default:"1000"`
	SourceSQLAuthKVBackend string `user:"true" help:"source key/value store backend (must be sqlauth) url" default:""`
}

// KV is an implementation of the KV interface that helps move from sqlauth to
// badgerauth backend by incorporating both, implementing migration and proxying
// requests to both backends to avoid downtime.
type KV struct {
	mon *monkit.Scope
	log *zap.Logger
	src *sqlauth.KV
	dst *badgerauth.Node

	config Config
}

// Below is a compile-time check ensuring KV implements the KV interface.
var (
	_ authdb.KV                                           = (*KV)(nil)
	_ interface{ MigrateToLatest(context.Context) error } = (*KV)(nil)
)

// New constructs new KV.
func New(log *zap.Logger, src *sqlauth.KV, dst *badgerauth.Node, config Config) *KV {
	return &KV{
		mon:    monkit.Package(),
		log:    log,
		src:    src,
		dst:    dst,
		config: config,
	}
}

// Put stores the record.
// It is an error if the key already exists.
//
// We write to both stores to ensure we can perform a rollback in case of
// anything.
func (kv *KV) Put(ctx context.Context, keyHash authdb.KeyHash, record *authdb.Record) (err error) {
	defer kv.mon.Task()(&ctx)(&err)

	// createdAt is truncated to Unix time to make sure both stores get the same
	// time. Otherwise, this could cause issues during the migration when
	// inserted times differ (get rounded) by a second. In that case, records
	// reimported to badgerauth by the migrator node wouldn't match and cancel
	// migration.
	createdAt := time.Unix(time.Now().Unix(), 0)

	if err := kv.src.PutAtTime(ctx, keyHash, record, createdAt); err != nil {
		return Error.New("failed to write to sqlauth: %w", err)
	}
	kv.log.Debug("Wrote to sqlauth", zap.Binary("keyHash", keyHash.Bytes()))
	if err := kv.dst.PutAtTime(ctx, keyHash, record, createdAt); err != nil {
		kv.mon.Event("as_badgerauthmigration_destination_put_err")
		return Error.New("failed to write to badgerauth: %w", err)
	}
	kv.log.Debug("Wrote to badgerauth", zap.Binary("keyHash", keyHash.Bytes()))
	return nil
}

// Get retrieves the record from the key/value store. It returns nil if the key
// does not exist. If the record is invalid, the error contains why.
func (kv *KV) Get(ctx context.Context, keyHash authdb.KeyHash) (record *authdb.Record, err error) {
	defer kv.mon.Task()(&ctx)(&err)
	// First, try to get the record from the destination store and only fall
	// back to source store if needed.
	record, err = kv.dst.Get(ctx, keyHash)
	if (record == nil || err != nil) && !authdb.Invalid.Has(err) {
		if err != nil {
			kv.log.Warn("unexpected destination store error @ Get", zap.Error(err))
		}
		record, err = kv.src.Get(ctx, keyHash)
		if record != nil && err == nil {
			kv.log.Warn(
				"destination miss",
				zap.String("keyHash (hex)", keyHash.ToHex()),
				zap.String("SatelliteAddress", record.SatelliteAddress),
				zap.Binary("MacaroonHead", record.MacaroonHead),
				zap.Timep("ExpiresAt", record.ExpiresAt),
			)
			kv.mon.Event("as_badgerauthmigration_destination_miss")
		}
	} else {
		kv.mon.Event("as_badgerauthmigration_destination_hit")
	}
	return record, Error.Wrap(err)
}

// DeleteUnused is not implemented.
func (*KV) DeleteUnused(context.Context, time.Duration, int, int) (int64, int64, map[string]int64, error) {
	return 0, 0, nil, Error.New("not implemented")
}

// PingDB attempts to do a database roundtrip and returns an error if it can't.
func (kv *KV) PingDB(ctx context.Context) (err error) {
	defer kv.mon.Task()(&ctx)(&err)

	return Error.Wrap(errs.Combine(kv.dst.PingDB(ctx), kv.src.PingDB(ctx)))
}

// Run runs the server and the associated servers.
func (kv *KV) Run(ctx context.Context) error {
	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		return kv.dst.Run(groupCtx)
	})
	group.Go(func() error {
		return kv.src.Run(groupCtx)
	})
	return Error.Wrap(group.Wait())
}

// MigrateToLatest migrates all existing records at passed sqlauth to the new
// badgerauth backend.
func (kv *KV) MigrateToLatest(ctx context.Context) error {
	srcDB := kv.src.UnderlyingDB()
	dstDB := kv.dst.UnderlyingDB().UnderlyingDB()

	recordsCount, err := srcDB.Count_Record(ctx)
	if err != nil {
		return Error.Wrap(err)
	}

	kv.log.Info("starting records migration", zap.Int64("cutoff", recordsCount))

	var (
		count      int64
		nextMarker *dbx.Paged_Record_Continuation
	)
	for {
		rows, next, err := srcDB.Paged_Record(ctx, kv.config.MigrationSelectSize, nextMarker)
		if err != nil {
			return Error.Wrap(err)
		}
		if err = dstDB.Update(func(txn *badger.Txn) error {
			for _, r := range rows {
				var keyHash authdb.KeyHash
				if err = keyHash.SetBytes(r.EncryptionKeyHash); err != nil {
					return err
				}
				if err = badgerauth.InsertRecord(kv.log, txn, kv.dst.ID(), keyHash, convertRecord(r)); err != nil {
					return err
				}
				count++
			}
			return nil
		}); err != nil {
			return Error.Wrap(err)
		}

		kv.log.Info("migrated another batch of records", zap.Int64("count", count))

		nextMarker = next

		if nextMarker == nil {
			kv.log.Info("finished records migration", zap.Int64("count", count), zap.Int64("cutoff", recordsCount))
			break
		}
	}

	return nil
}

func convertRecord(r *dbx.Record) *pb.Record {
	converted := &pb.Record{
		CreatedAtUnix:        r.CreatedAt.Unix(),
		Public:               r.Public,
		SatelliteAddress:     r.SatelliteAddress,
		MacaroonHead:         r.MacaroonHead,
		EncryptedSecretKey:   r.EncryptedSecretKey,
		EncryptedAccessGrant: r.EncryptedAccessGrant,
		State:                pb.Record_CREATED,
	}
	if r.ExpiresAt != nil {
		converted.ExpiresAtUnix = r.ExpiresAt.Unix()
	}
	if r.InvalidReason != nil {
		converted.InvalidationReason = *r.InvalidReason
	}
	if r.InvalidAt != nil {
		converted.InvalidatedAtUnix = r.InvalidAt.Unix()
	}

	return converted
}

// Close closes the database.
func (kv *KV) Close() (err error) {
	return Error.Wrap(errs.Combine(kv.dst.Close(), kv.src.Close()))
}
