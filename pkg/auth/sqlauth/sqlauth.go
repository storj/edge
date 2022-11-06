// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package sqlauth

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/gateway-mt/pkg/auth/authdb"
	"storj.io/gateway-mt/pkg/auth/sqlauth/dbx"
	"storj.io/private/dbutil"
	_ "storj.io/private/dbutil/cockroachutil" // register our custom driver
	"storj.io/private/dbutil/pgutil"
	"storj.io/private/dbutil/pgutil/pgerrcode"
	"storj.io/private/dbutil/tempdb"
	"storj.io/private/tagsql"
)

var mon = monkit.Package()

// Error is default error class for sqlauth package.
var Error = errs.Class("sqlauth")

// KV is a key/value store backed by a sql database.
type KV struct {
	db          *dbx.DB // DBX
	impl        dbutil.Implementation
	testCleanup func() error
}

// Options includes options for how a connection is made.
type Options struct {
	ApplicationName string
}

// Open creates instance of KV.
func Open(ctx context.Context, log *zap.Logger, connstr string, opts Options) (_ *KV, err error) {
	defer mon.Task()(&ctx)(&err)

	driver, source, impl, err := dbutil.SplitConnStr(connstr)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	if impl != dbutil.Postgres && impl != dbutil.Cockroach {
		return nil, Error.New("unsupported driver %q", driver)
	}

	source, err = pgutil.CheckApplicationName(source, opts.ApplicationName)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	dbxDB, err := dbx.Open(driver, source)
	if err != nil {
		return nil, Error.New("failed opening database via DBX at %q: %v", source, err)
	}
	log.Debug("Connected to:", zap.String("db source", source))

	dbutil.Configure(ctx, dbxDB.DB, "sqlauth", mon)

	return &KV{
		db:          dbxDB,
		impl:        impl,
		testCleanup: func() error { return nil },
	}, nil
}

// OpenTest creates an instance of KV suitable for testing.
func OpenTest(ctx context.Context, log *zap.Logger, name, connstr string) (*KV, error) {
	tempDB, err := tempdb.OpenUnique(ctx, connstr, name)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	kv, err := Open(ctx, log, tempDB.ConnStr, Options{ApplicationName: "test"})
	if err != nil {
		return nil, Error.Wrap(err)
	}

	kv.TestingSetCleanup(tempDB.Close)

	return kv, nil
}

// UnderlyingDB returns the underlying database.
func (d *KV) UnderlyingDB() *dbx.DB { return d.db }

// Schema returns the underlying database schema.
func (d *KV) Schema() string { return d.db.Schema() }

// TagSQL returns *tagsql.DB.
func (d *KV) TagSQL() tagsql.DB { return d.db.DB }

// Close closes the connection to database.
func (d *KV) Close() error {
	return errs.Combine(Error.Wrap(d.db.Close()), Error.Wrap(d.testCleanup()))
}

// Run runs the database.
func (d *KV) Run(ctx context.Context) error { return nil }

// TestingSetCleanup is used to set the callback for cleaning up test database.
func (d *KV) TestingSetCleanup(cleanup func() error) {
	d.testCleanup = cleanup
}

// MigrateToLatest migrates the kv store to the latest version of the schema.
func (d *KV) MigrateToLatest(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	log := zap.L().Named("migrate")
	migration := d.Migration(ctx)
	err = migration.Run(ctx, log)
	if err != nil {
		return Error.Wrap(err)
	}
	return migration.ValidateVersions(ctx, log)
}

// Put is like PutAtTime, but it uses current time to store the record.
func (d *KV) Put(ctx context.Context, keyHash authdb.KeyHash, record *authdb.Record) (err error) {
	defer mon.Task()(&ctx)(&err)

	return Error.Wrap(d.db.CreateNoReturn_Record(ctx,
		dbx.Record_EncryptionKeyHash(keyHash[:]),
		dbx.Record_CreatedAt(time.Now().UTC()),
		dbx.Record_Public(record.Public),
		dbx.Record_SatelliteAddress(record.SatelliteAddress),
		dbx.Record_MacaroonHead(record.MacaroonHead),
		dbx.Record_EncryptedSecretKey(record.EncryptedSecretKey),
		dbx.Record_EncryptedAccessGrant(record.EncryptedAccessGrant),
		dbx.Record_Create_Fields{
			ExpiresAt: dbx.Record_ExpiresAt_Raw(record.ExpiresAt),
		}))
}

// PutAtTime stores the record at a specific time.
// It is an error if the key already exists.
func (d *KV) PutAtTime(ctx context.Context, keyHash authdb.KeyHash, record *authdb.Record, createdAt time.Time) (err error) {
	defer mon.Task()(&ctx)(&err)

	return Error.Wrap(d.db.CreateNoReturn_Record(ctx,
		dbx.Record_EncryptionKeyHash(keyHash[:]),
		dbx.Record_CreatedAt(createdAt),
		dbx.Record_Public(record.Public),
		dbx.Record_SatelliteAddress(record.SatelliteAddress),
		dbx.Record_MacaroonHead(record.MacaroonHead),
		dbx.Record_EncryptedSecretKey(record.EncryptedSecretKey),
		dbx.Record_EncryptedAccessGrant(record.EncryptedAccessGrant),
		dbx.Record_Create_Fields{
			ExpiresAt: dbx.Record_ExpiresAt_Raw(record.ExpiresAt),
		}))
}

// Get retrieves the record from the key/value store.
func (d *KV) Get(ctx context.Context, keyHash authdb.KeyHash) (*authdb.Record, error) {
	return d.GetWithNonDefaultAsOfInterval(ctx, keyHash, -10*time.Second)
}

// GetWithNonDefaultAsOfInterval retrieves the record from the key/value store
// using the specific asOfSystemInterval.
func (d *KV) GetWithNonDefaultAsOfInterval(ctx context.Context, keyHash authdb.KeyHash, asOfSystemInterval time.Duration) (_ *authdb.Record, err error) {
	defer mon.Task()(&ctx)(&err)

	if d.impl == dbutil.Cockroach {
		query := `SELECT
					satellite_address,
					macaroon_head,
					encrypted_secret_key,
					encrypted_access_grant,
					expires_at,
					public,
					invalid_reason
		 	  FROM records ` + d.impl.AsOfSystemInterval(asOfSystemInterval) +
			` WHERE encryption_key_hash = $1`
		row := d.db.DB.QueryRowContext(ctx, query, keyHash[:])

		var (
			record        authdb.Record
			invalidReason sql.NullString
		)
		err = row.Scan(
			&record.SatelliteAddress, &record.MacaroonHead,
			&record.EncryptedSecretKey, &record.EncryptedAccessGrant, &record.ExpiresAt,
			&record.Public, &invalidReason,
		)
		if err == nil {
			if invalidReason.Valid {
				return nil, authdb.Invalid.New("%s", invalidReason.String)
			}
			if record.ExpiresAt != nil && record.ExpiresAt.Before(time.Now()) {
				return nil, nil
			}

			return &record, nil
		}

		if !errors.Is(err, sql.ErrNoRows) {
			// Check whether the error code is not about the database or table
			// not existing, which may happen if we run an AOST query right
			// after migration.
			if code := pgerrcode.FromError(err); code != "3D000" && code != "42P01" {
				return nil, Error.Wrap(err)
			}
		}

		// No results, then run a query without 'AS OF SYSTEM TIME' clause
	}

	dbRecord, err := d.db.Find_Record_By_EncryptionKeyHash(ctx,
		dbx.Record_EncryptionKeyHash(keyHash[:]))
	if err != nil {
		return nil, Error.Wrap(err)
	} else if dbRecord == nil {
		return nil, nil
	} else if dbRecord.InvalidReason != nil {
		return nil, authdb.Invalid.New("%s", *dbRecord.InvalidReason)
	} else if dbRecord.ExpiresAt != nil && dbRecord.ExpiresAt.Before(time.Now()) {
		return nil, nil
	}

	return &authdb.Record{
		SatelliteAddress:     dbRecord.SatelliteAddress,
		MacaroonHead:         dbRecord.MacaroonHead,
		EncryptedSecretKey:   dbRecord.EncryptedSecretKey,
		EncryptedAccessGrant: dbRecord.EncryptedAccessGrant,
		ExpiresAt:            dbRecord.ExpiresAt,
		Public:               dbRecord.Public,
	}, nil
}

// Delete removes the record from the key/value store.
// It is not an error if the key does not exist.
func (d *KV) Delete(ctx context.Context, keyHash authdb.KeyHash) (err error) {
	defer mon.Task()(&ctx)(&err)

	_, err = d.db.Delete_Record_By_EncryptionKeyHash(ctx,
		dbx.Record_EncryptionKeyHash(keyHash[:]))
	return Error.Wrap(err)
}

// selectUnused returns up to selectSize pkvals corresponding to unused (expired
// or invalid) records in a read-only transaction in the past as specified by
// the asOfSystemInterval interval.
func (d *KV) selectUnused(ctx context.Context, asOfSystemInterval time.Duration, selectSize int) (pkvals, heads [][]byte, err error) {
	defer mon.Task()(&ctx)(&err)

	tx, err := d.db.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, Error.Wrap(err)
	}

	// We don't commit the transaction and only roll it back, in any case, to
	// release any read locks early.
	defer func() { err = errs.Combine(err, Error.Wrap(tx.Rollback())) }()

	if d.impl == dbutil.Cockroach {
		if _, err = tx.ExecContext(
			ctx,
			"SET TRANSACTION"+d.impl.AsOfSystemInterval(-asOfSystemInterval),
		); err != nil {
			return nil, nil, Error.Wrap(err)
		}
	}

	rows, err := tx.QueryContext(
		ctx,
		`
		SELECT encryption_key_hash, macaroon_head
		FROM records
		WHERE expires_at < CURRENT_TIMESTAMP
		  OR invalid_at < CURRENT_TIMESTAMP
		ORDER BY encryption_key_hash
		LIMIT $1
		`,
		selectSize,
	)
	if err != nil {
		return nil, nil, Error.Wrap(err)
	}

	defer func() { err = errs.Combine(err, Error.Wrap(rows.Close())) }()

	for rows.Next() {
		var pkval, head []byte

		if err = rows.Scan(&pkval, &head); err != nil {
			return nil, nil, Error.Wrap(err)
		}

		pkvals, heads = append(pkvals, pkval), append(heads, head)
	}

	if err = rows.Err(); err != nil {
		return nil, nil, Error.Wrap(err)
	}

	return pkvals, heads, nil
}

// DeleteUnused deletes expired and invalid records from the key/value store in
// batches as specified by the selectSize and deleteSize parameters and returns
// any error encountered. It uses database time to avoid problems with invalid
// time on the server.
func (d *KV) DeleteUnused(ctx context.Context, asOfSystemInterval time.Duration, selectSize, deleteSize int) (count, rounds int64, deletesPerHead map[string]int64, err error) {
	defer mon.Task()(&ctx)(&err)

	deletesPerHead = make(map[string]int64)

	for {
		pkvals, heads, err := d.selectUnused(ctx, asOfSystemInterval, selectSize)
		if err != nil {
			return count, rounds, deletesPerHead, Error.Wrap(err)
		}

		if len(pkvals) == 0 {
			return count, rounds, deletesPerHead, nil
		}

		for len(pkvals) > 0 {
			var pkvalsBatch, headsBatch [][]byte

			pkvalsBatch, pkvals = BatchValues(pkvals, deleteSize)
			headsBatch, heads = BatchValues(heads, deleteSize)

			res, err := d.db.DB.ExecContext(
				ctx,
				`
				DELETE
				FROM records
				WHERE encryption_key_hash = ANY ($1::BYTEA[])
				`,
				pgutil.ByteaArray(pkvalsBatch),
			)
			if err != nil {
				return count, rounds, deletesPerHead, Error.Wrap(err)
			}

			c, err := res.RowsAffected()
			if err == nil { // Not every database or database driver may support RowsAffected.
				count += c
			}

			rounds++

			for _, h := range headsBatch {
				deletesPerHead[string(h)]++
			}
		}

		if d.impl == dbutil.Cockroach {
			time.Sleep(asOfSystemInterval)
		}
	}
}

// BatchValues splits pkvals into two groups, where the first has a maximum
// length of threshold and the second contains the rest of the data.
func BatchValues(pkvals [][]byte, threshold int) ([][]byte, [][]byte) {
	if len(pkvals) < threshold {
		return pkvals, nil
	}
	return pkvals[:threshold], pkvals[threshold:]
}

// Invalidate causes the record to become invalid.
// It is not an error if the key does not exist.
// It does not update the invalid reason if the record is already invalid.
func (d *KV) Invalidate(ctx context.Context, keyHash authdb.KeyHash, reason string) (err error) {
	defer mon.Task()(&ctx)(&err)

	return Error.Wrap(d.db.UpdateNoReturn_Record_By_EncryptionKeyHash_And_InvalidReason_Is_Null(ctx,
		dbx.Record_EncryptionKeyHash(keyHash[:]),
		dbx.Record_Update_Fields{
			InvalidReason: dbx.Record_InvalidReason(reason),
			InvalidAt:     dbx.Record_InvalidAt(time.Now()),
		}))
}

// PingDB attempts to do a database roundtrip and returns an error if it can't.
func (d *KV) PingDB(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	return Error.Wrap(d.db.PingContext(ctx))
}
