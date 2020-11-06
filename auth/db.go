// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"

	"github.com/zeebo/errs"

	"storj.io/common/encryption"
	"storj.io/common/storj"
	"storj.io/uplink/private/access2"
)

// NotFound is returned when a record is not found.
var NotFound = errs.Class("not found")

// EncryptionKey is an encryption key that an access/secret are encrypted with.
type EncryptionKey [32]byte

// Hash returns the KeyHash for the EncryptionKey.
func (k EncryptionKey) Hash() KeyHash {
	return KeyHash(sha256.Sum256(k[:]))
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
func (db *Database) Put(ctx context.Context, key EncryptionKey, accessGrant string, public bool) (
	secretKey []byte, err error) {
	defer mon.Task()(&ctx)(&err)

	access, err := access2.ParseAccess(accessGrant)
	if err != nil {
		return nil, err
	}
	_ = access // TODO: use access below

	secretKey = make([]byte, 32)
	if _, err := rand.Read(secretKey); err != nil {
		return nil, err
	}

	storjKey := storj.Key(key)
	nonce := &storj.Nonce{}

	encryptedSecretKey, err := encryption.Encrypt(secretKey, storj.EncAESGCM, &storjKey, nonce)
	if err != nil {
		return nil, err
	}

	if _, err := encryption.Increment(nonce, 1); err != nil {
		return nil, err
	}

	encryptedAccessGrant, err := encryption.Encrypt([]byte(accessGrant), storj.EncAESGCM, &storjKey, nonce)
	if err != nil {
		return nil, err
	}

	// TODO: Verify access with satellite.
	// TODO: Verify satellite address is on whitelist.

	record := &Record{
		SatelliteAddress:     access.SatelliteAddress,
		MacaroonHead:         access.APIKey.Head(),
		EncryptedSecretKey:   encryptedSecretKey,
		EncryptedAccessGrant: encryptedAccessGrant,
		Public:               public,
	}

	if err := db.kv.Put(ctx, key.Hash(), record); err != nil {
		return nil, errs.Wrap(err)
	}

	return secretKey, err
}

// Get retrieves an access grant and secret key from the key/value store, looked up by the
// hash of the key and decrypted.
func (db *Database) Get(ctx context.Context, key EncryptionKey) (accessGrant string, public bool, secretKey []byte, err error) {
	defer mon.Task()(&ctx)(&err)

	record, err := db.kv.Get(ctx, key.Hash())
	if err != nil {
		return "", false, nil, errs.Wrap(err)
	} else if record == nil {
		return "", false, nil, NotFound.New("key hash: %x", key.Hash())
	}

	nonce := &storj.Nonce{}

	storjKey := storj.Key(key)
	secretKey, err = encryption.Decrypt(record.EncryptedSecretKey, storj.EncAESGCM, &storjKey, nonce)
	if err != nil {
		return "", false, nil, errs.Wrap(err)
	}

	if _, err := encryption.Increment(nonce, 1); err != nil {
		return "", false, nil, errs.Wrap(err)
	}

	ag, err := encryption.Decrypt(record.EncryptedAccessGrant, storj.EncAESGCM, &storjKey, nonce)
	if err != nil {
		return "", false, nil, errs.Wrap(err)
	}

	return string(ag), record.Public, secretKey, nil
}

// Delete removes any access grant information from the key/value store, looked up by the
// hash of the key.
func (db *Database) Delete(ctx context.Context, key EncryptionKey) (err error) {
	defer mon.Task()(&ctx)(&err)

	return errs.Wrap(db.kv.Delete(ctx, key.Hash()))
}

// Invalidate causes the access to become invalid.
func (db *Database) Invalidate(ctx context.Context, key EncryptionKey, reason string) (err error) {
	defer mon.Task()(&ctx)(&err)

	return errs.Wrap(db.kv.Invalidate(ctx, key.Hash(), reason))
}
