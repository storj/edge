// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package sqlauth

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"time"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/gateway-mt/auth"
	"storj.io/private/dbutil"
)

var mon = monkit.Package()

//go:generate sh gen.sh

// KV is a key/value store backed by a SQL database.
type KV struct {
	db   *DB // DBX
	impl dbutil.Implementation
}

// OpenKV opens a DB connection to the key/value store.
// It returns an error  if the dbURL is not valid, the DB implementation isn't
// supported or if it isn't possible to establish a connection with the DB.
func OpenKV(ctx context.Context, dbURL string) (*KV, error) {
	parsed, err := url.Parse(dbURL)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	var (
		impl = dbutil.Cockroach
		db   *DB
	)
	switch parsed.Scheme {
	case "postgres", "pgx":
		impl = dbutil.Postgres
		fallthrough
	case "pgxcockroach", "cockroach":
		parsed.Scheme = "postgres"
		db, err = Open("pgxcockroach", parsed.String())
		if err != nil {
			return nil, errs.Wrap(err)
		}
	default:
		return nil, errs.New("unknown scheme: %q", dbURL)
	}

	kv := &KV{db: db, impl: impl}
	if err := kv.Ping(ctx); err != nil {
		return nil, err
	}

	return kv, nil
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

	return errs.Wrap(d.db.CreateNoReturn_Record(ctx,
		Record_EncryptionKeyHash(keyHash[:]),
		Record_Public(record.Public),
		Record_SatelliteAddress(record.SatelliteAddress),
		Record_MacaroonHead(record.MacaroonHead),
		Record_EncryptedSecretKey(record.EncryptedSecretKey),
		Record_EncryptedAccessGrant(record.EncryptedAccessGrant),
		Record_Create_Fields{},
	))
}

// Get retrieves the record from the key/value store.
func (d *KV) Get(ctx context.Context, keyHash auth.KeyHash) (_ *auth.Record, err error) {
	defer mon.Task()(&ctx)(&err)

	query := `SELECT
			satellite_address,
			macaroon_head,
			encrypted_secret_key,
			encrypted_access_grant,
			public,
			invalid_reason ` + d.impl.AsOfSystemInterval(10*time.Second) +
		`FROM records
		WHERE
			encryption_key_hash = $1`
	row := d.db.DB.QueryRowContext(ctx, query, keyHash[:])

	var (
		satelliteAddr  string
		mhead          []byte
		encSecretKey   []byte
		encAccessGrant []byte
		isPublic       bool
		invalidReason  sql.NullString
	)
	err = row.Scan(&satelliteAddr, &mhead, &encSecretKey, &encAccessGrant, &isPublic, &invalidReason)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}

		return nil, errs.Wrap(err)
	}

	if invalidReason.Valid {
		return nil, auth.Invalid.New("%s", invalidReason.String)
	}

	return &auth.Record{
		SatelliteAddress:     satelliteAddr,
		MacaroonHead:         mhead,
		EncryptedSecretKey:   encSecretKey,
		EncryptedAccessGrant: encAccessGrant,
		Public:               isPublic,
	}, nil
}

// Delete removes the record from the key/value store.
// It is not an error if the key does not exist.
func (d *KV) Delete(ctx context.Context, keyHash auth.KeyHash) (err error) {
	defer mon.Task()(&ctx)(&err)

	_, err = d.db.Delete_Record_By_EncryptionKeyHash(ctx,
		Record_EncryptionKeyHash(keyHash[:]))
	return errs.Wrap(err)
}

// Invalidate causes the record to become invalid.
// It is not an error if the key does not exist.
// It does not update the invalid reason if the record is already invalid.
func (d *KV) Invalidate(ctx context.Context, keyHash auth.KeyHash, reason string) (err error) {
	defer mon.Task()(&ctx)(&err)

	return errs.Wrap(d.db.UpdateNoReturn_Record_By_EncryptionKeyHash_And_InvalidReason_Is_Null(ctx,
		Record_EncryptionKeyHash(keyHash[:]),
		Record_Update_Fields{
			InvalidReason: Record_InvalidReason(reason),
			InvalidAt:     Record_InvalidAt(time.Now()),
		}))
}

// Ping attempts to do a database roundtrip and returns an error if it can't.
func (d *KV) Ping(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	return errs.Wrap(d.db.PingContext(ctx))
}
