// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package sqlauth

import (
	"context"
	"time"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/gateway-mt/auth/store"
)

var mon = monkit.Package()

//go:generate sh gen.sh

// KV is a key/value store backed by a sql database.
type KV struct {
	db *DB // DBX
}

// New returns a SQL implementation of a key-value store.
func New(db *DB) *KV {
	return &KV{db: db}
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
func (d *KV) Put(ctx context.Context, keyHash store.KeyHash, record *store.Record) (err error) {
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
func (d *KV) Get(ctx context.Context, keyHash store.KeyHash) (record *store.Record, err error) {
	defer mon.Task()(&ctx)(&err)

	dbRecord, err := d.db.Find_Record_By_EncryptionKeyHash(ctx,
		Record_EncryptionKeyHash(keyHash[:]))
	if err != nil {
		return nil, errs.Wrap(err)
	} else if dbRecord == nil {
		return nil, nil
	} else if dbRecord.InvalidReason != nil {
		return nil, store.Invalid.New("%s", *dbRecord.InvalidReason)
	}

	return &store.Record{
		SatelliteAddress:     dbRecord.SatelliteAddress,
		MacaroonHead:         dbRecord.MacaroonHead,
		EncryptedSecretKey:   dbRecord.EncryptedSecretKey,
		EncryptedAccessGrant: dbRecord.EncryptedAccessGrant,
		Public:               dbRecord.Public,
	}, nil
}

// Delete removes the record from the key/value store.
// It is not an error if the key does not exist.
func (d *KV) Delete(ctx context.Context, keyHash store.KeyHash) (err error) {
	defer mon.Task()(&ctx)(&err)

	_, err = d.db.Delete_Record_By_EncryptionKeyHash(ctx,
		Record_EncryptionKeyHash(keyHash[:]))
	return errs.Wrap(err)
}

// Invalidate causes the record to become invalid.
// It is not an error if the key does not exist.
// It does not update the invalid reason if the record is already invalid.
func (d *KV) Invalidate(ctx context.Context, keyHash store.KeyHash, reason string) (err error) {
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
