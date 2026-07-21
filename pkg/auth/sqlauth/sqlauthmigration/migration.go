// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package sqlauthmigration

import (
	"context"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/errs2"
	"storj.io/edge/pkg/auth/authdb"
	"storj.io/edge/pkg/auth/spannerauth"
	"storj.io/edge/pkg/auth/sqlauth"
)

var (
	_ authdb.StorageAdmin = (*Storage)(nil)
	_ interface {
		MigrateToLatest(context.Context) error
	} = (*Storage)(nil)

	// Error is the class of sqlauthmigration errors.
	Error = errs.Class("sqlauthmigration")
)

// Storage migrates from a spanner source to a sqlauth destination.
type Storage struct {
	mon *monkit.Scope
	log *zap.Logger
	src *spannerauth.CloudDatabase
	dst *sqlauth.KV
}

// New constructs a Storage.
func New(log *zap.Logger, src *spannerauth.CloudDatabase, dst *sqlauth.KV) *Storage {
	return &Storage{mon: monkit.Package(), log: log, src: src, dst: dst}
}

// Put writes to both backends (spanner then sqlauth).
func (s *Storage) Put(ctx context.Context, keyHash authdb.KeyHash, record *authdb.Record) (err error) {
	defer s.mon.Task()(&ctx)(&err)
	if err := s.src.Put(ctx, keyHash, record); err != nil {
		return Error.New("failed to write to spanner: %w", err)
	}
	if err := s.dst.Put(ctx, keyHash, record); err != nil {
		if !errs2.IsCanceled(err) {
			s.mon.Event("as_sqlauthmigration_destination_put_err")
		}
		return Error.New("failed to write to sqlauth: %w", err)
	}
	return nil
}

// MigrateToLatest ensures the sqlauth schema exists and backfills every
// record from the spanner source into it. It is idempotent: records that
// already exist in the destination are treated as already-migrated, not
// as errors, so re-running the backfill (e.g. after a partial failure) is
// safe.
func (s *Storage) MigrateToLatest(ctx context.Context) (err error) {
	defer s.mon.Task()(&ctx)(&err)

	if err := s.dst.MigrateToLatest(ctx); err != nil {
		return Error.Wrap(err)
	}
	return Error.Wrap(s.src.IterateAll(ctx, func(ctx context.Context, kh authdb.KeyHash, r *authdb.FullRecord) error {
		if err := s.dst.PutFullRecord(ctx, kh, r); err != nil && !sqlauth.IsDuplicate(err) {
			return err
		}
		return nil
	}))
}

// Get reads sqlauth first, falling back to spanner.
func (s *Storage) Get(ctx context.Context, keyHash authdb.KeyHash) (record *authdb.Record, err error) {
	defer s.mon.Task()(&ctx)(&err)
	record, err = s.dst.Get(ctx, keyHash)
	if (record == nil || err != nil) && !errs2.IsCanceled(err) && !authdb.Invalid.Has(err) {
		if err != nil {
			s.log.Warn("unexpected destination error @ Get", zap.Error(err))
		}
		record, err = s.src.Get(ctx, keyHash)
		if record != nil && err == nil {
			s.mon.Event("as_sqlauthmigration_destination_miss")
		}
	} else {
		s.mon.Event("as_sqlauthmigration_destination_hit")
	}
	return record, Error.Wrap(err)
}

// GetFullRecord reads sqlauth first, falling back to spanner only on a
// clean (nil,nil) miss from the destination — unlike Get, it does not fall
// back on a destination error; that hot-path resilience isn't needed here.
func (s *Storage) GetFullRecord(ctx context.Context, keyHash authdb.KeyHash) (*authdb.FullRecord, error) {
	r, err := s.dst.GetFullRecord(ctx, keyHash)
	if r == nil && err == nil {
		return s.src.GetFullRecord(ctx, keyHash)
	}
	return r, Error.Wrap(err)
}

// Invalidate applies the mutation to both backends and combines their
// errors. If the destination (sqlauth) leg fails after the source
// (spanner) leg succeeds, the record is left inconsistent in the
// destination — which Get/GetFullRecord read first — until the operator
// retries. MigrateToLatest's backfill does not reconcile this: it skips
// keys that already exist in the destination (via IsDuplicate), so it
// never revisits already-migrated rows.
func (s *Storage) Invalidate(ctx context.Context, keyHash authdb.KeyHash, reason string) error {
	return Error.Wrap(errs.Combine(s.src.Invalidate(ctx, keyHash, reason), s.dst.Invalidate(ctx, keyHash, reason)))
}

// Unpublish proxies to both backends.
func (s *Storage) Unpublish(ctx context.Context, keyHash authdb.KeyHash) error {
	return Error.Wrap(errs.Combine(s.src.Unpublish(ctx, keyHash), s.dst.Unpublish(ctx, keyHash)))
}

// Delete proxies to both backends.
func (s *Storage) Delete(ctx context.Context, keyHash authdb.KeyHash) error {
	return Error.Wrap(errs.Combine(s.src.Delete(ctx, keyHash), s.dst.Delete(ctx, keyHash)))
}

// HealthCheck checks both backends.
func (s *Storage) HealthCheck(ctx context.Context) error {
	return Error.Wrap(errs.Combine(s.dst.HealthCheck(ctx), s.src.HealthCheck(ctx)))
}

// Close closes both backends.
func (s *Storage) Close() error {
	return Error.Wrap(errs.Combine(s.dst.Close(), s.src.Close()))
}
