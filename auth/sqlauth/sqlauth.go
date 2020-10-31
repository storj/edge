// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package sqlauth

import (
	"context"
	"time"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"

	"storj.io/stargate/auth"
)

var mon = monkit.Package()

//go:generate sh gen.sh

// KV is a key/value store backed by a sql database.
type KV struct {
	db *DB
}

// New wraps the sql database into a KV.
func New(db *DB) *KV {
	return &KV{
		db: db,
	}
}

// Put stores the record in the key/value store.
// It is an error if the key already exists.
func (d *KV) Put(ctx context.Context, keyHash auth.KeyHash, record *auth.Record) (err error) {
	defer mon.Task()(&ctx)(&err)

	return errs.Wrap(d.db.CreateNoReturn_Record(ctx,
		Record_EncryptionKeyHash(keyHash[:]),
		Record_SatelliteAddress(record.SatelliteAddress),
		Record_MacaroonHead(record.MacaroonHead),
		Record_EncryptedSecretKey(record.EncryptedSecretKey),
		Record_EncryptedAccessGrant(record.EncryptedAccessGrant),
		Record_Create_Fields{},
	))
}

// Get retrieves the record from the key/value store.
func (d *KV) Get(ctx context.Context, keyHash auth.KeyHash) (record *auth.Record, err error) {
	defer mon.Task()(&ctx)(&err)

	dbRecord, err := d.db.Find_Record_By_EncryptionKeyHash(ctx,
		Record_EncryptionKeyHash(keyHash[:]))
	if err != nil {
		return nil, errs.Wrap(err)
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
