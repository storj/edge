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

	"storj.io/gateway-mt/auth"
	"storj.io/gateway-mt/auth/sqlauth/dbx"
	"storj.io/private/dbutil"
	_ "storj.io/private/dbutil/cockroachutil" // register our custom driver
	"storj.io/private/dbutil/pgutil"
	"storj.io/private/dbutil/pgutil/pgerrcode"
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
func Open(ctx context.Context, log *zap.Logger, connstr string, opts Options) (*KV, error) {
	driver, source, impl, err := dbutil.SplitConnStr(connstr)
	if err != nil {
		return nil, err
	}
	if impl != dbutil.Postgres && impl != dbutil.Cockroach {
		return nil, Error.New("unsupported driver %q", driver)
	}

	source, err = pgutil.CheckApplicationName(source, opts.ApplicationName)
	if err != nil {
		return nil, err
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

// TestingSchema returns the underlying database schema.
func (d *KV) TestingSchema() string { return d.db.Schema() }

// TestingTagSQL returns *tagsql.DB.
func (d *KV) TestingTagSQL() tagsql.DB { return d.db.DB }

// Close closes the connection to database.
func (d *KV) Close() error {
	return errs.Combine(Error.Wrap(d.db.Close()), Error.Wrap(d.testCleanup()))
}

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
		return err
	}
	return migration.ValidateVersions(ctx, log)
}

// Put stores the record in the key/value store.
// It is an error if the key already exists.
func (d *KV) Put(ctx context.Context, keyHash auth.KeyHash, record *auth.Record) (err error) {
	defer mon.Task()(&ctx)(&err)

	return Error.Wrap(d.db.CreateNoReturn_Record(ctx,
		dbx.Record_EncryptionKeyHash(keyHash[:]),
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
func (d *KV) Get(ctx context.Context, keyHash auth.KeyHash) (_ *auth.Record, err error) {
	return d.GetWithNonDefaultAsOfInterval(ctx, keyHash, -10*time.Second)
}

// GetWithNonDefaultAsOfInterval retrieves the record from the key/value store
// using the specific asOfSystemInterval.
func (d *KV) GetWithNonDefaultAsOfInterval(ctx context.Context, keyHash auth.KeyHash, asOfSystemInterval time.Duration) (record *auth.Record, err error) {
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
			record        auth.Record
			invalidReason sql.NullString
		)
		err = row.Scan(
			&record.SatelliteAddress, &record.MacaroonHead,
			&record.EncryptedSecretKey, &record.EncryptedAccessGrant, &record.ExpiresAt,
			&record.Public, &invalidReason,
		)
		if err == nil {
			if invalidReason.Valid {
				return nil, auth.Invalid.New("%s", invalidReason.String)
			}

			return &record, nil
		}

		if !errors.Is(err, sql.ErrNoRows) {
			// Check that the error isn't about that the table isn't defined which can
			// happen if the service runs just after the DB migration which creates
			// the table and it starts to serve requests before the
			// 'AS OF SYSTEM TIME' has passed since the migrations has ended.
			if code := pgerrcode.FromError(err); code != "42P01" {
				return nil, errs.Wrap(err)
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
		return nil, auth.Invalid.New("%s", *dbRecord.InvalidReason)
	}

	return &auth.Record{
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
func (d *KV) Delete(ctx context.Context, keyHash auth.KeyHash) (err error) {
	defer mon.Task()(&ctx)(&err)

	_, err = d.db.Delete_Record_By_EncryptionKeyHash(ctx,
		dbx.Record_EncryptionKeyHash(keyHash[:]))
	return Error.Wrap(err)
}

// Invalidate causes the record to become invalid.
// It is not an error if the key does not exist.
// It does not update the invalid reason if the record is already invalid.
func (d *KV) Invalidate(ctx context.Context, keyHash auth.KeyHash, reason string) (err error) {
	defer mon.Task()(&ctx)(&err)

	return Error.Wrap(d.db.UpdateNoReturn_Record_By_EncryptionKeyHash_And_InvalidReason_Is_Null(ctx,
		dbx.Record_EncryptionKeyHash(keyHash[:]),
		dbx.Record_Update_Fields{
			InvalidReason: dbx.Record_InvalidReason(reason),
			InvalidAt:     dbx.Record_InvalidAt(time.Now()),
		}))
}

// Ping attempts to do a database roundtrip and returns an error if it can't.
func (d *KV) Ping(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	return Error.Wrap(d.db.PingContext(ctx))
}
