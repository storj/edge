// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package sqlauth

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/uuid"
	"storj.io/edge/internal/dbutil"
	"storj.io/edge/internal/dbutil/pgtest"
	"storj.io/edge/pkg/auth/authdb"
	"storj.io/edge/pkg/auth/sqlauth/dbx"
)

var (
	mon = monkit.Package()
	// Error is the default error class for the sqlauth package.
	Error = errs.Class("sqlauth")

	_ authdb.Storage      = (*KV)(nil)
	_ authdb.StorageAdmin = (*KV)(nil)
)

// Config configures the sqlauth backend.
type Config struct {
	URL             string        `user:"true" help:"PostgreSQL connection URL for the sqlauth backend"`
	ApplicationName string        `internal:"true"`
	MaxOpenConns    int           `user:"true" help:"maximum number of open connections" default:"25"`
	MaxIdleConns    int           `user:"true" help:"maximum number of idle connections" default:"25"`
	ConnMaxLifetime time.Duration `user:"true" help:"maximum lifetime of a connection (recycles after RDS failover)" default:"30m"`
	ConnMaxIdleTime time.Duration `user:"true" help:"maximum time a connection may sit idle before it is closed (0 disables)" default:"0"`
}

// Options are per-connection options.
type Options struct {
	ApplicationName string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
}

// KV is a PostgreSQL-backed authdb.StorageAdmin.
type KV struct {
	db          *dbx.DB
	testCleanup func() error
}

// Open opens a sqlauth KV against the given Postgres URL.
func Open(ctx context.Context, log *zap.Logger, connstr string, opts Options) (_ *KV, err error) {
	defer mon.Task()(&ctx)(&err)

	driver, source, impl, err := dbutil.SplitConnStr(connstr)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	if impl != dbutil.Postgres {
		return nil, Error.New("unsupported implementation for %q; only PostgreSQL is supported", connstr)
	}

	dbxDB, err := dbx.Open(driver, source)
	if err != nil {
		return nil, Error.New("opening database: %w", err)
	}
	if opts.MaxOpenConns > 0 {
		dbxDB.DB.SetMaxOpenConns(opts.MaxOpenConns)
	}
	if opts.MaxIdleConns > 0 {
		dbxDB.DB.SetMaxIdleConns(opts.MaxIdleConns)
	}
	if opts.ConnMaxLifetime > 0 {
		dbxDB.DB.SetConnMaxLifetime(opts.ConnMaxLifetime)
	}
	if opts.ConnMaxIdleTime > 0 {
		dbxDB.DB.SetConnMaxIdleTime(opts.ConnMaxIdleTime)
	}
	log.Debug("connected", zap.String("impl", "postgres"))

	return &KV{db: dbxDB, testCleanup: func() error { return nil }}, nil
}

// OpenTest opens a KV backed by a unique temporary database.
func OpenTest(ctx context.Context, log *zap.Logger, name, connstr string) (*KV, error) {
	tempDB, err := pgtest.OpenUnique(ctx, connstr, name)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	kv, err := Open(ctx, log, tempDB.ConnStr, Options{ApplicationName: "test"})
	if err != nil {
		return nil, errs.Combine(Error.Wrap(err), tempDB.Close())
	}
	kv.testCleanup = tempDB.Close
	return kv, nil
}

// HealthCheck pings the database.
func (d *KV) HealthCheck(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)
	return Error.Wrap(d.db.PingContext(ctx))
}

// Close closes the database (and any test cleanup).
func (d *KV) Close() error {
	return errs.Combine(Error.Wrap(d.db.Close()), Error.Wrap(d.testCleanup()))
}

// underlyingDB exposes the raw *sql.DB for migrations/enumeration.
func (d *KV) underlyingDB() *sql.DB { return d.db.DB }

// Put stores the record. It is an error if the key already exists.
func (d *KV) Put(ctx context.Context, keyHash authdb.KeyHash, record *authdb.Record) (err error) {
	defer mon.Task()(&ctx)(&err)

	var fields dbx.Record_Create_Fields
	if record.ExpiresAt != nil && !record.ExpiresAt.IsZero() {
		fields.ExpiresAt = dbx.Record_ExpiresAt(*record.ExpiresAt)
	}
	if record.PublicProjectID != nil && !bytes.Equal(record.PublicProjectID, uuid.UUID{}.Bytes()) {
		fields.PublicProjectId = dbx.Record_PublicProjectId(record.PublicProjectID)
	}
	if len(record.UsageTags) > 0 {
		for _, tag := range record.UsageTags {
			if strings.Contains(tag, ",") {
				return Error.New("usage tags can't contain commas")
			}
		}
		fields.UsageTags = dbx.Record_UsageTags(strings.Join(record.UsageTags, ","))
	}
	if !record.ProjectCreatedAt.IsZero() {
		fields.ProjectCreatedAt = dbx.Record_ProjectCreatedAt(record.ProjectCreatedAt)
	}

	return Error.Wrap(d.db.CreateNoReturn_Record(ctx,
		dbx.Record_EncryptionKeyHash(keyHash[:]),
		dbx.Record_CreatedAt(time.Now().UTC()),
		dbx.Record_Public(record.Public),
		dbx.Record_SatelliteAddress(record.SatelliteAddress),
		dbx.Record_MacaroonHead(record.MacaroonHead),
		dbx.Record_EncryptedSecretKey(record.EncryptedSecretKey),
		dbx.Record_EncryptedAccessGrant(record.EncryptedAccessGrant),
		fields,
	))
}

// PutFullRecord stores the full record, preserving its CreatedAt and
// invalidation fields verbatim rather than stamping a fresh created_at (as
// Put does). It is meant for backfilling from another backend; it is an
// error (detectable via IsDuplicate) if the key already exists.
func (d *KV) PutFullRecord(ctx context.Context, keyHash authdb.KeyHash, r *authdb.FullRecord) (err error) {
	defer mon.Task()(&ctx)(&err)

	var fields dbx.Record_Create_Fields
	if r.ExpiresAt != nil && !r.ExpiresAt.IsZero() {
		fields.ExpiresAt = dbx.Record_ExpiresAt(*r.ExpiresAt)
	}
	if r.PublicProjectID != nil && !bytes.Equal(r.PublicProjectID, uuid.UUID{}.Bytes()) {
		fields.PublicProjectId = dbx.Record_PublicProjectId(r.PublicProjectID)
	}
	if len(r.UsageTags) > 0 {
		for _, tag := range r.UsageTags {
			if strings.Contains(tag, ",") {
				return Error.New("usage tags can't contain commas")
			}
		}
		fields.UsageTags = dbx.Record_UsageTags(strings.Join(r.UsageTags, ","))
	}
	if !r.ProjectCreatedAt.IsZero() {
		fields.ProjectCreatedAt = dbx.Record_ProjectCreatedAt(r.ProjectCreatedAt)
	}
	if r.InvalidationReason != "" {
		fields.InvalidationReason = dbx.Record_InvalidationReason(r.InvalidationReason)
	}
	if !r.InvalidatedAt.IsZero() {
		fields.InvalidatedAt = dbx.Record_InvalidatedAt(r.InvalidatedAt)
	}

	return Error.Wrap(d.db.CreateNoReturn_Record(ctx,
		dbx.Record_EncryptionKeyHash(keyHash[:]),
		dbx.Record_CreatedAt(r.CreatedAt),
		dbx.Record_Public(r.Public),
		dbx.Record_SatelliteAddress(r.SatelliteAddress),
		dbx.Record_MacaroonHead(r.MacaroonHead),
		dbx.Record_EncryptedSecretKey(r.EncryptedSecretKey),
		dbx.Record_EncryptedAccessGrant(r.EncryptedAccessGrant),
		fields,
	))
}

// IsDuplicate returns true if err represents a Postgres unique-violation
// (SQLSTATE 23505), e.g. from a Put/PutFullRecord racing or re-running
// against a key that already exists.
func IsDuplicate(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}

// Get retrieves the record. Returns (nil,nil) if absent or expired; Invalid if invalidated.
func (d *KV) Get(ctx context.Context, keyHash authdb.KeyHash) (_ *authdb.Record, err error) {
	full, err := d.GetFullRecord(ctx, keyHash)
	if err != nil || full == nil {
		return nil, err
	}
	if full.IsInvalid() {
		return nil, Error.Wrap(authdb.Invalid.New("%s", full.InvalidationReason))
	}
	return &full.Record, nil
}

// GetFullRecord retrieves the full record. Returns (nil,nil) if absent or expired.
func (d *KV) GetFullRecord(ctx context.Context, keyHash authdb.KeyHash) (_ *authdb.FullRecord, err error) {
	defer mon.Task()(&ctx)(&err)

	dbRecord, err := d.db.Get_Record_By_EncryptionKeyHash(ctx, dbx.Record_EncryptionKeyHash(keyHash[:]))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, Error.Wrap(err)
	}

	full := &authdb.FullRecord{
		Record: authdb.Record{
			SatelliteAddress:     dbRecord.SatelliteAddress,
			MacaroonHead:         dbRecord.MacaroonHead,
			EncryptedSecretKey:   dbRecord.EncryptedSecretKey,
			EncryptedAccessGrant: dbRecord.EncryptedAccessGrant,
			ExpiresAt:            dbRecord.ExpiresAt,
			Public:               dbRecord.Public,
			PublicProjectID:      dbRecord.PublicProjectId,
		},
		CreatedAt: dbRecord.CreatedAt,
	}
	if dbRecord.UsageTags != nil && len(*dbRecord.UsageTags) > 0 {
		full.UsageTags = strings.Split(*dbRecord.UsageTags, ",")
	}
	if dbRecord.ProjectCreatedAt != nil {
		full.ProjectCreatedAt = *dbRecord.ProjectCreatedAt
	}
	if dbRecord.InvalidationReason != nil {
		full.InvalidationReason = *dbRecord.InvalidationReason
	}
	if dbRecord.InvalidatedAt != nil {
		full.InvalidatedAt = *dbRecord.InvalidatedAt
	}

	if full.ExpiresAt != nil && full.ExpiresAt.Before(time.Now()) {
		return nil, nil
	}
	return full, nil
}

// Invalidate marks the record invalid (no-op if already invalid).
func (d *KV) Invalidate(ctx context.Context, keyHash authdb.KeyHash, reason string) (err error) {
	defer mon.Task()(&ctx)(&err)
	return Error.Wrap(d.db.UpdateNoReturn_Record_By_EncryptionKeyHash_And_InvalidationReason_Is_Null(ctx,
		dbx.Record_EncryptionKeyHash(keyHash[:]),
		dbx.Record_Update_Fields{
			InvalidationReason: dbx.Record_InvalidationReason(reason),
			InvalidatedAt:      dbx.Record_InvalidatedAt(time.Now()),
		}))
}

// Unpublish makes the record non-public.
func (d *KV) Unpublish(ctx context.Context, keyHash authdb.KeyHash) (err error) {
	defer mon.Task()(&ctx)(&err)
	_, err = d.underlyingDB().ExecContext(ctx,
		`UPDATE records SET public = false WHERE encryption_key_hash = $1`, keyHash[:])
	return Error.Wrap(err)
}

// Delete removes the record (not an error if absent).
func (d *KV) Delete(ctx context.Context, keyHash authdb.KeyHash) (err error) {
	defer mon.Task()(&ctx)(&err)
	_, err = d.db.Delete_Record_By_EncryptionKeyHash(ctx, dbx.Record_EncryptionKeyHash(keyHash[:]))
	return Error.Wrap(err)
}
