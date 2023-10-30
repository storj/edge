// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package spannerauthmigration

import (
	"context"
	"encoding/hex"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/outcaste-io/badger/v3"
	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"

	"storj.io/edge/pkg/auth/authdb"
	"storj.io/edge/pkg/auth/badgerauth"
	"storj.io/edge/pkg/auth/badgerauth/pb"
	"storj.io/edge/pkg/auth/spannerauth"
)

var (
	_ authdb.Storage                                      = (*Storage)(nil)
	_ interface{ MigrateToLatest(context.Context) error } = (*Storage)(nil)

	// Error is a class of spannerauthmigration errors.
	Error = errs.Class("spannerauthmigration")
)

// Storage is an implementation of the Storage interface for migrating from badgerauth source
// backend to the spannerauth destination backend. It proxies requests to avoid downtime.
type Storage struct {
	mon *monkit.Scope
	log *zap.Logger
	src *badgerauth.Node
	dst *spannerauth.CloudDatabase
}

// New constructs a new Storage.
func New(log *zap.Logger, src *badgerauth.Node, dst *spannerauth.CloudDatabase) *Storage {
	return &Storage{
		mon: monkit.Package(),
		log: log,
		src: src,
		dst: dst,
	}
}

// Put stores the record, writing it to both source and destination backends.
func (s *Storage) Put(ctx context.Context, keyHash authdb.KeyHash, record *authdb.Record) (err error) {
	defer s.mon.Task()(&ctx)(&err)

	if err := s.src.Put(ctx, keyHash, record); err != nil {
		return Error.New("failed to write to badgerauth: %s", err)
	}
	s.log.Debug("Wrote to badgerauth", zap.String("keyHash", keyHash.ToHex()))
	if err := s.dst.Put(ctx, keyHash, record); err != nil {
		s.mon.Event("as_spannerauthmigration_destination_put_err")
		return Error.New("failed to write to spannerauth: %w", err)
	}
	s.log.Debug("Wrote to spannerauth", zap.String("keyHash", keyHash.ToHex()))

	return nil
}

// Get gets the record, retrieving it from the source backend if it doesn't exist in the destination backend.
func (s *Storage) Get(ctx context.Context, keyHash authdb.KeyHash) (record *authdb.Record, err error) {
	defer s.mon.Task()(&ctx)(&err)

	record, err = s.dst.Get(ctx, keyHash)
	if (record == nil || err != nil) && !authdb.Invalid.Has(err) {
		if err != nil {
			s.log.Warn("unexpected destination store error @ Get", zap.Error(err))
		}
		record, err = s.src.Get(ctx, keyHash)
		if record != nil && err == nil {
			s.log.Warn(
				"destination miss",
				zap.String("keyHash", keyHash.ToHex()),
				zap.String("SatelliteAddress", record.SatelliteAddress),
				zap.String("MacaroonHead", hex.EncodeToString(record.MacaroonHead)),
				zap.Timep("ExpiresAt", record.ExpiresAt),
			)
			s.mon.Event("as_spannerauthmigration_destination_miss")
		}
	} else {
		s.mon.Event("as_spannerauthmigration_destination_hit")
	}

	return record, Error.Wrap(err)
}

// HealthCheck attempts to do a database roundtrip and returns an error if it can't.
func (s *Storage) HealthCheck(ctx context.Context) (err error) {
	defer s.mon.Task()(&ctx)(&err)

	return Error.Wrap(errs.Combine(s.dst.HealthCheck(ctx), s.src.HealthCheck(ctx)))
}

// Run runs the server and associated servers.
func (s *Storage) Run(ctx context.Context) error {
	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		return s.dst.Run(groupCtx)
	})
	group.Go(func() error {
		return s.src.Run(groupCtx)
	})

	return Error.Wrap(group.Wait())
}

// Close closes the database.
func (s *Storage) Close() (err error) {
	return Error.Wrap(errs.Combine(s.dst.Close(), s.src.Close()))
}

// MigrateToLatest migrates existing records from the source to destination backends.
func (s *Storage) MigrateToLatest(ctx context.Context) error {
	return Error.Wrap(s.src.UnderlyingDB().UnderlyingDB().View(func(txn *badger.Txn) error {
		opt := badger.DefaultIteratorOptions

		it := txn.NewIterator(opt)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			keyBytes := it.Item().KeyCopy(nil)

			var clock badgerauth.Clock
			if err := it.Item().Value(clock.SetBytes); err == nil {
				s.log.Debug("skipping clock record", zap.Uint64("clock", uint64(clock)))
				continue
			}

			var rl badgerauth.ReplicationLogEntry
			if err := rl.SetBytes(keyBytes); err == nil {
				s.log.Debug("skipping replication log entry record",
					zap.String("nodeID", rl.ID.String()),
					zap.Uint64("clock", uint64(rl.Clock)),
					zap.String("keyHash", rl.KeyHash.ToHex()),
					zap.String("state", rl.State.String()))
				continue
			}

			// KeyHash.SetBytes only checks the length is not too long, so we
			// can't rely on that to match record bytes to a KeyHash
			if len(keyBytes) != len(authdb.KeyHash{}) {
				s.log.Debug("skipping unknown record", zap.ByteString("key", keyBytes))
				continue
			}

			var keyHash authdb.KeyHash
			if err := keyHash.SetBytes(keyBytes); err != nil {
				return err
			}

			var pbr pb.Record
			if err := it.Item().Value(func(val []byte) error {
				return pb.Unmarshal(val, &pbr)
			}); err != nil {
				return err
			}

			if pbr.InvalidationReason != "" {
				s.log.Debug("skipping invalidated record", zap.String("keyHash", keyHash.ToHex()))
				continue
			}

			var expiresAt time.Time
			if pbr.ExpiresAtUnix > 0 {
				expiresAt = time.Unix(pbr.ExpiresAtUnix, 0)
			}

			record := &authdb.Record{
				SatelliteAddress:     pbr.SatelliteAddress,
				MacaroonHead:         pbr.MacaroonHead,
				EncryptedSecretKey:   pbr.EncryptedSecretKey,
				EncryptedAccessGrant: pbr.EncryptedAccessGrant,
				ExpiresAt:            &expiresAt,
				Public:               pbr.Public,
			}

			var createdAt time.Time
			if pbr.CreatedAtUnix > 0 {
				createdAt = time.Unix(pbr.CreatedAtUnix, 0)
			}

			if err := s.dst.PutWithCreatedAt(ctx, keyHash, record, createdAt); err != nil {
				if spanner.ErrCode(err) == codes.AlreadyExists {
					s.log.Debug("record already exists at destination", zap.String("keyHash", keyHash.ToHex()))
					continue
				}
				return err
			}
		}

		return nil
	}))
}
