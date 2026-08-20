// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package sqlauth

import (
	"bytes"
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/zeebo/errs"

	"storj.io/common/uuid"
	"storj.io/edge/pkg/auth/authdb"
)

var bulkColumns = []string{
	"encryption_key_hash", "created_at", "public", "public_project_id",
	"satellite_address", "macaroon_head", "expires_at",
	"encrypted_secret_key", "encrypted_access_grant",
	"invalidation_reason", "invalidated_at", "usage_tags", "project_created_at",
}

// BulkWriter bulk-loads FullRecords into a KV's records table in batches,
// deduplicating against existing rows. See KV.NewBulkWriter.
//
// Not safe for concurrent use: BulkPutFullRecords issues three separate
// statements (COPY, then INSERT ... SELECT, then TRUNCATE) on the one
// connection this writer pins, and database/sql only serializes at
// statement granularity, so two goroutines sharing a writer can interleave
// their statements and silently lose a batch. Each concurrent caller (e.g.
// one worker per backfill partition) must use its own BulkWriter.
type BulkWriter struct {
	conn *sql.Conn
}

// NewBulkWriter pins a dedicated connection and prepares a session-scoped
// staging table for BulkPutFullRecords. The caller must Close it when done.
// Close returns the connection to the pool rather than ending the Postgres
// session, so the staging table does not actually get dropped then; instead,
// NewBulkWriter unconditionally drops and recreates it on every call, so a
// pinned connection handed back by a previous BulkWriter always starts with
// an empty table matching the current records schema, even if records
// itself changed shape since that connection last held a staging table.
func (d *KV) NewBulkWriter(ctx context.Context) (_ *BulkWriter, err error) {
	defer mon.Task()(&ctx)(&err)

	conn, err := d.underlyingDB().Conn(ctx)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	if _, err := conn.ExecContext(ctx, `DROP TABLE IF EXISTS records_staging`); err != nil {
		return nil, Error.Wrap(errs.Combine(err, conn.Close()))
	}
	if _, err := conn.ExecContext(ctx,
		`CREATE TEMPORARY TABLE records_staging (LIKE records INCLUDING DEFAULTS) ON COMMIT PRESERVE ROWS`); err != nil {
		return nil, Error.Wrap(errs.Combine(err, conn.Close()))
	}
	return &BulkWriter{conn: conn}, nil
}

// Close releases the pinned connection; its staging table drops with it.
func (w *BulkWriter) Close() error {
	return Error.Wrap(w.conn.Close())
}

// BulkPutFullRecords loads a batch of records in a single round trip via
// COPY into the session's staging table, then moves only not-yet-present
// rows into records via ON CONFLICT (encryption_key_hash) DO NOTHING, and
// empties the staging table again. Rows whose key already exists in the
// destination (whether previously loaded through this writer, an earlier
// BulkWriter, or a plain Put) are left untouched, never overwritten. Safe to
// call repeatedly with overlapping batches.
func (w *BulkWriter) BulkPutFullRecords(ctx context.Context, keyHashes []authdb.KeyHash, records []*authdb.FullRecord) (err error) {
	defer mon.Task()(&ctx)(&err)

	if len(keyHashes) != len(records) {
		return Error.New("keyHashes and records must be the same length")
	}
	if len(keyHashes) == 0 {
		return nil
	}

	rows := make([][]any, len(keyHashes))
	for i, r := range records {
		var usageTags *string
		if len(r.UsageTags) > 0 {
			for _, tag := range r.UsageTags {
				if strings.Contains(tag, ",") {
					return Error.New("usage tags can't contain commas")
				}
			}
			joined := strings.Join(r.UsageTags, ",")
			usageTags = &joined
		}
		var projectCreatedAt *time.Time
		if !r.ProjectCreatedAt.IsZero() {
			t := r.ProjectCreatedAt
			projectCreatedAt = &t
		}
		var invalidationReason *string
		if r.InvalidationReason != "" {
			invalidationReason = &r.InvalidationReason
		}
		var invalidatedAt *time.Time
		if !r.InvalidatedAt.IsZero() {
			t := r.InvalidatedAt
			invalidatedAt = &t
		}
		var publicProjectID []byte
		if len(r.PublicProjectID) > 0 && !bytes.Equal(r.PublicProjectID, uuid.UUID{}.Bytes()) {
			publicProjectID = r.PublicProjectID
		}
		var expiresAt *time.Time
		if r.ExpiresAt != nil && !r.ExpiresAt.IsZero() {
			expiresAt = r.ExpiresAt
		}
		rows[i] = []any{
			keyHashes[i].Bytes(), r.CreatedAt, r.Public, publicProjectID,
			r.SatelliteAddress, r.MacaroonHead, expiresAt,
			r.EncryptedSecretKey, r.EncryptedAccessGrant,
			invalidationReason, invalidatedAt, usageTags, projectCreatedAt,
		}
	}

	if err := w.conn.Raw(func(driverConn any) error {
		pgxConn := driverConn.(*stdlib.Conn).Conn()
		_, err := pgxConn.CopyFrom(ctx, pgx.Identifier{"records_staging"}, bulkColumns, pgx.CopyFromRows(rows))
		return err
	}); err != nil {
		return Error.Wrap(err)
	}

	if _, err := w.conn.ExecContext(ctx, `INSERT INTO records SELECT * FROM records_staging
		ON CONFLICT (encryption_key_hash) DO NOTHING`); err != nil {
		return Error.Wrap(err)
	}
	if _, err := w.conn.ExecContext(ctx, `TRUNCATE records_staging`); err != nil {
		return Error.Wrap(err)
	}
	return nil
}
