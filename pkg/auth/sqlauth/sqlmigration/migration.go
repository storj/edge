// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package sqlmigration

import (
	"context"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/errs2"
	"storj.io/edge/pkg/auth/authdb"
	"storj.io/edge/pkg/auth/sqlauth"
)

var (
	_ authdb.StorageAdmin = (*Storage)(nil)
	_ interface {
		MigrateToLatest(context.Context) error
	} = (*Storage)(nil)

	// Error is the class of sqlmigration errors.
	Error = errs.Class("sqlmigration")
)

// Options configures backfill throughput for MigrateToLatest.
type Options struct {
	// Concurrency is the number of parallel key-range workers used by the
	// backfill. Values <= 0 default to 16. Each worker holds a connection to
	// both databases for as long as its partition takes, so this must be
	// sized against their pools; it is not validated. See README.md.
	Concurrency int
	// BatchSize is the number of rows per bulk-copy batch during the
	// backfill. Values <= 0 default to 5000.
	BatchSize int
}

func (o Options) normalized() Options {
	if o.Concurrency <= 0 {
		o.Concurrency = 16
	}
	if o.BatchSize <= 0 {
		o.BatchSize = 5000
	}
	return o
}

// Storage migrates from a sqlauth source to a sqlauth destination: writes go
// to both, reads prefer the destination and fall back to the source, and
// MigrateToLatest backfills existing source records into the destination.
type Storage struct {
	mon  *monkit.Scope
	log  *zap.Logger
	src  *sqlauth.KV
	dst  *sqlauth.KV
	opts Options
}

// New constructs a Storage.
func New(log *zap.Logger, src, dst *sqlauth.KV, opts Options) *Storage {
	return &Storage{mon: monkit.Package(), log: log, src: src, dst: dst, opts: opts.normalized()}
}

// Put writes to both backends (source then destination).
func (s *Storage) Put(ctx context.Context, keyHash authdb.KeyHash, record *authdb.Record) (err error) {
	defer s.mon.Task()(&ctx)(&err)
	if err := s.src.Put(ctx, keyHash, record); err != nil {
		return Error.New("failed to write to source: %w", err)
	}
	if err := s.dst.Put(ctx, keyHash, record); err != nil {
		if sqlauth.IsDuplicate(err) {
			// The common case is a concurrently-running backfill having
			// already copied this exact key from src into dst (IterateRange
			// is a live scan over a live table, so it can race in a row this
			// call just wrote to src moments ago), which is not a failure:
			// the record is correctly present in dst either way. But dst
			// could instead hold a different, stale record under this key
			// (e.g. an orphan left behind by a Delete whose src leg
			// succeeded and dst leg didn't) - this code can't tell the two
			// apart, so it reports success either way. Emit an event so the
			// divergent case is at least observable rather than silent.
			s.mon.Event("as_sqlmigration_destination_put_duplicate")
			return nil
		}
		if !errs2.IsCanceled(err) {
			s.mon.Event("as_sqlmigration_destination_put_err")
		}
		return Error.New("failed to write to destination: %w", err)
	}
	return nil
}

// Get reads the destination first, falling back to the source on a miss or
// an unexpected destination error.
func (s *Storage) Get(ctx context.Context, keyHash authdb.KeyHash) (record *authdb.Record, err error) {
	defer s.mon.Task()(&ctx)(&err)
	record, err = s.dst.Get(ctx, keyHash)
	if (record == nil || err != nil) && !errs2.IsCanceled(err) && !authdb.Invalid.Has(err) {
		if err != nil {
			s.log.Warn("unexpected destination error @ Get", zap.Error(err))
		}
		record, err = s.src.Get(ctx, keyHash)
		if record != nil && err == nil {
			s.mon.Event("as_sqlmigration_destination_miss")
		}
	} else {
		s.mon.Event("as_sqlmigration_destination_hit")
	}
	return record, Error.Wrap(err)
}

// GetFullRecord reads the destination first, falling back to the source
// only on a clean (nil,nil) miss; unlike Get, it does not fall back on a
// destination error; that hot-path resilience isn't needed here.
func (s *Storage) GetFullRecord(ctx context.Context, keyHash authdb.KeyHash) (*authdb.FullRecord, error) {
	r, err := s.dst.GetFullRecord(ctx, keyHash)
	if r == nil && err == nil {
		return s.src.GetFullRecord(ctx, keyHash)
	}
	return r, Error.Wrap(err)
}

// Invalidate applies the mutation to both backends and combines their errors.
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

// MigrateToLatest ensures the destination schema exists and backfills every
// record from the source into it, using Options.Concurrency parallel
// key-range workers that each write via a BulkWriter in batches of
// Options.BatchSize. It only ever inserts: rows already present in the
// destination are left untouched, so re-running it after a partial failure is
// safe.
//
// This scans the whole source table and blocks until it finishes, so it is
// meant to run as a standalone job rather than as part of server startup, and
// admin mutations must reach both databases for as long as the migration
// window is open. See README.md for the rollout it expects.
func (s *Storage) MigrateToLatest(ctx context.Context) (err error) {
	defer s.mon.Task()(&ctx)(&err)

	if err := s.dst.MigrateToLatest(ctx); err != nil {
		return Error.Wrap(err)
	}

	if err := s.backfill(ctx); err != nil {
		return Error.Wrap(err)
	}

	return nil
}
