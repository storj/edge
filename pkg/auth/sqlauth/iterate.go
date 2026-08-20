// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package sqlauth

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"storj.io/edge/pkg/auth/authdb"
)

const iterateAllPageSize = 1000

const iterateQueryNoUpper = `SELECT encryption_key_hash, created_at, public, public_project_id,
	satellite_address, macaroon_head, expires_at,
	encrypted_secret_key, encrypted_access_grant,
	invalidation_reason, invalidated_at, usage_tags, project_created_at
FROM records
WHERE encryption_key_hash > $1
ORDER BY encryption_key_hash
LIMIT $2`

const iterateQueryWithUpper = `SELECT encryption_key_hash, created_at, public, public_project_id,
	satellite_address, macaroon_head, expires_at,
	encrypted_secret_key, encrypted_access_grant,
	invalidation_reason, invalidated_at, usage_tags, project_created_at
FROM records
WHERE encryption_key_hash > $1 AND encryption_key_hash < $2
ORDER BY encryption_key_hash
LIMIT $3`

// IterateAll calls fn for every record in the table, in ascending order of
// encryption key hash, including expired and invalidated ones: callers
// doing migration/backfill need the full set; any filtering (e.g. of
// expired records) is left to the caller. Equivalent to
// IterateRange(ctx, nil, nil, fn).
func (d *KV) IterateAll(ctx context.Context, fn func(context.Context, authdb.KeyHash, *authdb.FullRecord) error) (err error) {
	defer mon.Task()(&ctx)(&err)
	return d.IterateRange(ctx, nil, nil, fn)
}

// IterateRange is like IterateAll, but restricted to keys in the open range
// (lo, hi): the lower bound is EXCLUSIVE (a key equal to lo is skipped) and
// the upper bound is exclusive too. A nil lo means "no lower bound", a nil
// hi means "no upper bound". Used to split the table into disjoint,
// independently-scannable partitions for parallel backfill, where lo is
// always a 1-byte prefix boundary that no 32-byte key hash can equal, so
// the exclusive lower bound never drops a row.
func (d *KV) IterateRange(ctx context.Context, lo, hi []byte, fn func(context.Context, authdb.KeyHash, *authdb.FullRecord) error) (err error) {
	defer mon.Task()(&ctx)(&err)

	cursor := lo
	if cursor == nil {
		cursor = []byte{}
	}

	for {
		var (
			rows    *sql.Rows
			pageErr error
		)
		if hi == nil {
			rows, pageErr = d.underlyingDB().QueryContext(ctx, iterateQueryNoUpper, cursor, iterateAllPageSize)
		} else {
			rows, pageErr = d.underlyingDB().QueryContext(ctx, iterateQueryWithUpper, cursor, hi, iterateAllPageSize)
		}
		if pageErr != nil {
			return Error.Wrap(pageErr)
		}

		count, last, scanErr := scanIteratePage(ctx, rows, fn)
		if scanErr != nil {
			return Error.Wrap(scanErr)
		}
		if count < iterateAllPageSize {
			return nil
		}
		cursor = last
	}
}

// iteratePageRow is one decoded row of a page, held only long enough to be
// handed to fn after the page's connection has been released.
type iteratePageRow struct {
	kh     authdb.KeyHash
	record *authdb.FullRecord
}

// scanIteratePage decodes an entire page and closes rows before calling fn
// for any of it, rather than calling fn from inside the rows.Next() loop.
// fn is caller code that, for the documented migration/backfill use case,
// does its own I/O (e.g. a bulk write) and IterateRange is meant to be run
// over many partitions concurrently; calling fn while this page's row still
// holds a connection checked out of the pool risks that I/O blocking on the
// same pool this scan is drawing from, and deadlocking rather than erroring.
func scanIteratePage(ctx context.Context, rows *sql.Rows, fn func(context.Context, authdb.KeyHash, *authdb.FullRecord) error) (count int, last []byte, err error) {
	page, last, err := decodeIteratePage(rows)
	if err != nil {
		return 0, last, err
	}

	for _, row := range page {
		if err := fn(ctx, row.kh, row.record); err != nil {
			return count, last, err
		}
		count++
	}
	return count, last, nil
}

func decodeIteratePage(rows *sql.Rows) (page []iteratePageRow, last []byte, err error) {
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			khBytes                       []byte
			createdAt                     time.Time
			public                        bool
			publicProjectID, macaroonHead []byte
			satelliteAddress              string
			expiresAt                     sql.NullTime
			encryptedSecretKey            []byte
			encryptedAccessGrant          []byte
			invalidationReason            sql.NullString
			invalidatedAt                 sql.NullTime
			usageTags                     sql.NullString
			projectCreatedAt              sql.NullTime
		)
		if err := rows.Scan(&khBytes, &createdAt, &public, &publicProjectID,
			&satelliteAddress, &macaroonHead, &expiresAt,
			&encryptedSecretKey, &encryptedAccessGrant,
			&invalidationReason, &invalidatedAt, &usageTags, &projectCreatedAt); err != nil {
			return page, last, err
		}

		var kh authdb.KeyHash
		if err := kh.SetBytes(khBytes); err != nil {
			return page, last, err
		}

		full := &authdb.FullRecord{
			Record: authdb.Record{
				SatelliteAddress:     satelliteAddress,
				MacaroonHead:         macaroonHead,
				EncryptedSecretKey:   encryptedSecretKey,
				EncryptedAccessGrant: encryptedAccessGrant,
				Public:               public,
				PublicProjectID:      publicProjectID,
			},
			CreatedAt: createdAt,
		}
		if expiresAt.Valid {
			t := expiresAt.Time
			full.ExpiresAt = &t
		}
		if usageTags.Valid && usageTags.String != "" {
			full.UsageTags = strings.Split(usageTags.String, ",")
		}
		if projectCreatedAt.Valid {
			full.ProjectCreatedAt = projectCreatedAt.Time
		}
		if invalidationReason.Valid {
			full.InvalidationReason = invalidationReason.String
		}
		if invalidatedAt.Valid {
			full.InvalidatedAt = invalidatedAt.Time
		}

		page = append(page, iteratePageRow{kh: kh, record: full})
		last = khBytes
	}
	return page, last, rows.Err()
}
