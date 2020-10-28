// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package auth

import (
	"context"

	"github.com/zeebo/blake3"
	"github.com/zeebo/errs"

	"storj.io/uplink"
)

// NotFound is returned when a record is not found.
var NotFound = errs.Class("not found")

// EncryptionKey is an encryption key that an access/secret are encrypted with.
type EncryptionKey [32]byte

// Hash returns the KeyHash for the EncryptionKey.
func (k EncryptionKey) Hash() KeyHash {
	return KeyHash(blake3.Sum256(k[:]))
}

// Database wraps a key/value store and uses it to store encrypted accesses and secrets.
type Database struct {
	kv KV
}

// NewDatabase constructs a Database.
func NewDatabase(kv KV) *Database {
	return &Database{kv: kv}
}

// Put encrypts the access grant with the key and stores it in a key/value store under the
// hash of the encryption key.
func (db *Database) Put(ctx context.Context, key EncryptionKey, accessGrant string) (secretKey []byte, err error) {
	defer mon.Task()(&ctx)(&err)

	access, err := uplink.ParseAccess(accessGrant)
	if err != nil {
		return nil, err
	}
	_ = access // TODO: use access below

	secretKey = []byte("TODO")      // TODO: generate
	encryptedSecretKey := secretKey // TODO: encrypt

	record := &Record{
		SatelliteAddress:     "TODO",         // TODO: extend something to read this
		MacaroonHead:         []byte("TODO"), // TODO: extend something to read this
		EncryptedSecretKey:   encryptedSecretKey,
		EncryptedAccessGrant: []byte(accessGrant), // TODO: encrypt this
	}

	if err := db.kv.Put(ctx, key.Hash(), record); err != nil {
		return nil, errs.Wrap(err)
	}

	return encryptedSecretKey, err
}

// Get retreives an access grant and secret key from the key/value store, looked up by the
// hash of the key and decrypted.
func (db *Database) Get(ctx context.Context, key EncryptionKey) (accessGrant string, secretKey []byte, err error) {
	defer mon.Task()(&ctx)(&err)

	record, err := db.kv.Get(ctx, key.Hash())
	if err != nil {
		return "", nil, errs.Wrap(err)
	} else if record == nil {
		return "", nil, NotFound.New("key hash: %x", key.Hash())
	}

	secretKey = record.EncryptedSecretKey             // TODO: decrypt this
	accessGrant = string(record.EncryptedAccessGrant) // TODO: decrypt this

	return accessGrant, secretKey, nil
}
