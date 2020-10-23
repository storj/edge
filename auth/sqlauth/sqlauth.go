// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package sqlauth

import (
	"context"

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
	))
}

// Get retreives the record from the key/value store.
func (d *KV) Get(ctx context.Context, keyHash auth.KeyHash) (record *auth.Record, err error) {
	defer mon.Task()(&ctx)(&err)

	dbRecord, err := d.db.Find_Record_By_EncryptionKeyHash(ctx,
		Record_EncryptionKeyHash(keyHash[:]))
	if err != nil {
		return nil, errs.Wrap(err)
	} else if dbRecord == nil {
		return nil, nil
	}

	return &auth.Record{
		SatelliteAddress:     dbRecord.SatelliteAddress,
		MacaroonHead:         dbRecord.MacaroonHead,
		EncryptedSecretKey:   dbRecord.EncryptedSecretKey,
		EncryptedAccessGrant: dbRecord.EncryptedAccessGrant,
	}, nil
}
