// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"strings"

	"github.com/zeebo/errs"

	"storj.io/common/encryption"
	"storj.io/common/storj"
	"storj.io/uplink/private/access2"
)

// NotFound is returned when a record is not found.
var NotFound = errs.Class("not found")
var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

const eKeySizeEncoded = 28   // size in base32 bytes + magic byte
const versionByte = byte(77) // magic number for v1 EncryptionKey encoding

// EncryptionKey is an encryption key that an access/secret are encrypted with.
type EncryptionKey [16]byte

// NewEncryptionKey returns a new random EncryptionKey with initial version byte.
func NewEncryptionKey() (EncryptionKey, error) {
	key := EncryptionKey{versionByte}
	if _, err := rand.Read(key[:]); err != nil {
		return key, err
	}
	return key, nil
}

// Hash returns the KeyHash for the EncryptionKey.
func (k EncryptionKey) Hash() KeyHash {
	return KeyHash(sha256.Sum256(k[:]))
}

// FromBase32 loads the EncryptionKey from a lowercase RFC 4648 base32 string.
func (k *EncryptionKey) FromBase32(encoded string) error {
	if len(encoded) != eKeySizeEncoded {
		return errs.New("alphanumeric encryption key length expected to be %d, was %d", eKeySizeEncoded, len(encoded))
	}
	data, err := base32Encoding.DecodeString(strings.ToUpper(encoded))
	if err != nil {
		return errs.Wrap(err)
	}
	if data[0] != versionByte {
		return errs.New("encryption key did not start with expected byte")
	}
	copy(k[:], data[1:]) // overwrite k
	return nil
}

// ToBase32 returns the EncryptionKey as a lowercase RFC 4648 base32 string.
func (k EncryptionKey) ToBase32() string {
	keyWithMagic := append([]byte{versionByte}, k[:]...)
	return strings.ToLower(base32Encoding.EncodeToString(keyWithMagic))
}

// ToStorjKey returns the storj.Key equivalent for the EncryptionKey.
func (k EncryptionKey) ToStorjKey() storj.Key {
	var storjKey storj.Key
	copy(storjKey[:], k[:])
	return storjKey
}

// Database wraps a key/value store and uses it to store encrypted accesses and secrets.
type Database struct {
	kv                        KV
	allowedSatelliteAddresses map[string]struct{}
}

// NewDatabase constructs a Database. allowedSatelliteAddresses should contain
// the full URL (without a node ID), including port, for which satellites we
// allow for incoming access grants.
func NewDatabase(kv KV, allowedSatelliteAddresses []string) *Database {
	m := make(map[string]struct{}, len(allowedSatelliteAddresses))
	for _, sat := range allowedSatelliteAddresses {
		m[sat] = struct{}{}
	}
	return &Database{
		kv:                        kv,
		allowedSatelliteAddresses: m,
	}
}

// RemoveNodeIDs removes the nodeIDs from a list of valid node URLs. This can
// be called prior to NewDatabase to prepare allowed satellite addresses.
func RemoveNodeIDs(ss []string) (p []string, err error) {
	for _, s := range ss {
		url, err := storj.ParseNodeURL(s)
		if err != nil {
			return nil, err
		}
		p = append(p, url.Address)
	}
	return p, nil
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

	// Check that the satellite address embedded in the access grant is on the
	// allowed list.
	satelliteAddr := access.SatelliteAddress
	url, err := storj.ParseNodeURL(satelliteAddr)
	if err != nil {
		return nil, err
	}
	if _, ok := db.allowedSatelliteAddresses[url.Address]; !ok {
		return nil, errs.New("access grant contains disallowed satellite")
	}

	secretKey = make([]byte, 32)
	if _, err := rand.Read(secretKey); err != nil {
		return nil, err
	}

	storjKey := key.ToStorjKey()
	// note that we currently always use the same nonce here - all zero's for secret keys
	encryptedSecretKey, err := encryption.Encrypt(secretKey, storj.EncAESGCM, &storjKey, &storj.Nonce{})
	if err != nil {
		return nil, err
	}
	// note that we currently always use the same nonce here - one then all zero's for access grants
	encryptedAccessGrant, err := encryption.Encrypt([]byte(accessGrant), storj.EncAESGCM, &storjKey, &storj.Nonce{1})
	if err != nil {
		return nil, err
	}

	// TODO: Verify access with satellite.
	record := &Record{
		SatelliteAddress:     satelliteAddr,
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

	storjKey := key.ToStorjKey()
	// note that we currently always use the same nonce here - all zero's for secret keys
	secretKey, err = encryption.Decrypt(record.EncryptedSecretKey, storj.EncAESGCM, &storjKey, &storj.Nonce{})
	if err != nil {
		return "", false, nil, errs.Wrap(err)
	}
	// note that we currently always use the same nonce here - one then all zero's for access grants
	ag, err := encryption.Decrypt(record.EncryptedAccessGrant, storj.EncAESGCM, &storjKey, &storj.Nonce{1})
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
