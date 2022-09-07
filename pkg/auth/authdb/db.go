// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package authdb

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"strings"
	"sync"
	"time"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"

	"storj.io/common/encryption"
	"storj.io/common/grant"
	"storj.io/common/macaroon"
	"storj.io/common/pb"
	"storj.io/common/storj"
	"storj.io/gateway-mt/pkg/auth/satellitelist"
)

var mon = monkit.Package()

// NotFound is returned when a record is not found.
var NotFound = errs.Class("not found")
var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// EncKeySizeEncoded is size in base32 bytes + magic byte.
const EncKeySizeEncoded = 28

const encKeyVersionByte = byte(77) // magic number for v1 EncryptionKey encoding
const secKeyVersionByte = byte(78) // magic number for v1 SecretKey encoding

// EncryptionKey is an encryption key that an access/secret are encrypted with.
type EncryptionKey [16]byte

// SecretKey is the secret key used to sign requests.
type SecretKey [32]byte

// NewEncryptionKey returns a new random EncryptionKey with initial version byte.
func NewEncryptionKey() (EncryptionKey, error) {
	key := EncryptionKey{encKeyVersionByte}
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
	if len(encoded) != EncKeySizeEncoded {
		return errs.New("alphanumeric encryption key length expected to be %d, was %d", EncKeySizeEncoded, len(encoded))
	}
	data, err := base32Encoding.DecodeString(strings.ToUpper(encoded))
	if err != nil {
		return errs.Wrap(err)
	}
	err = k.FromBinary(data)
	if err != nil {
		return err
	}
	return nil
}

// FromBinary reads the key from binary which must include the version byte.
func (k *EncryptionKey) FromBinary(data []byte) error {
	if data[0] != encKeyVersionByte {
		return errs.New("encryption key did not start with expected byte")
	}
	copy(k[:], data[1:]) // overwrite k
	return nil
}

// ToBase32 returns the EncryptionKey as a lowercase RFC 4648 base32 string.
func (k EncryptionKey) ToBase32() string {
	return toBase32(k.ToBinary())
}

// ToBinary returns the EncryptionKey including the version byte.
func (k EncryptionKey) ToBinary() []byte {
	return append([]byte{encKeyVersionByte}, k[:]...)
}

// ToStorjKey returns the storj.Key equivalent for the EncryptionKey.
func (k EncryptionKey) ToStorjKey() storj.Key {
	var storjKey storj.Key
	copy(storjKey[:], k[:])
	return storjKey
}

// ToBase32 returns the SecretKey as a lowercase RFC 4648 base32 string.
func (s SecretKey) ToBase32() string {
	return toBase32(s.ToBinary())
}

// ToBinary returns the SecretKey including the version byte.
func (s SecretKey) ToBinary() []byte {
	return append([]byte{secKeyVersionByte}, s[:]...)
}

// toBase32 returns the buffer as a lowercase RFC 4648 base32 string.
func toBase32(k []byte) string {
	return strings.ToLower(base32Encoding.EncodeToString(k))
}

// Database wraps a key/value store and uses it to store encrypted accesses and secrets.
type Database struct {
	kv KV

	mu                   sync.Mutex
	allowedSatelliteURLs map[storj.NodeURL]struct{}
}

// NewDatabase constructs a Database. allowedSatelliteAddresses should contain
// the full URL (with a node ID), including port, for each satellite we
// allow for incoming access grants.
func NewDatabase(kv KV, allowedSatelliteURLs map[storj.NodeURL]struct{}) *Database {
	return &Database{
		kv:                   kv,
		allowedSatelliteURLs: allowedSatelliteURLs,
	}
}

// SetAllowedSatellites updates the allowed satellites list from configuration values.
func (db *Database) SetAllowedSatellites(allowedSatelliteURLs map[storj.NodeURL]struct{}) {
	db.mu.Lock()
	db.allowedSatelliteURLs = allowedSatelliteURLs
	db.mu.Unlock()
}

// Put encrypts the access grant with the key and stores it in a key/value store under the
// hash of the encryption key.
func (db *Database) Put(ctx context.Context, key EncryptionKey, accessGrant string, public bool) (secretKey SecretKey, err error) {
	defer mon.Task()(&ctx)(&err)

	access, err := grant.ParseAccess(accessGrant)
	if err != nil {
		return secretKey, err
	}

	// Check that the satellite address embedded in the access grant is on the
	// allowed list.
	satelliteAddr := access.SatelliteAddress
	nodeURL, err := satellitelist.ParseSatelliteURL(satelliteAddr)
	if err != nil {
		return secretKey, err
	}
	mon.Event("as_region_use_put", monkit.NewSeriesTag("satellite", satelliteAddr))

	db.mu.Lock()
	_, ok := db.allowedSatelliteURLs[nodeURL]
	db.mu.Unlock()
	if !ok {
		return secretKey, errs.New("access grant contains disallowed satellite %q", satelliteAddr)
	}

	if _, err := rand.Read(secretKey[:]); err != nil {
		return secretKey, err
	}

	storjKey := key.ToStorjKey()
	// note that we currently always use the same nonce here - all zero's for secret keys
	encryptedSecretKey, err := encryption.Encrypt(secretKey[:], storj.EncAESGCM, &storjKey, &storj.Nonce{})
	if err != nil {
		return secretKey, err
	}
	// note that we currently always use the same nonce here - one then all zero's for access grants
	encryptedAccessGrant, err := encryption.Encrypt([]byte(accessGrant), storj.EncAESGCM, &storjKey, &storj.Nonce{1})
	if err != nil {
		return secretKey, err
	}

	expiration, err := apiKeyExpiration(access.APIKey)
	if err != nil {
		return secretKey, err
	}

	record := &Record{
		SatelliteAddress:     satelliteAddr,
		MacaroonHead:         access.APIKey.Head(),
		EncryptedSecretKey:   encryptedSecretKey,
		EncryptedAccessGrant: encryptedAccessGrant,
		Public:               public,
		ExpiresAt:            expiration,
	}

	if err := db.kv.Put(ctx, key.Hash(), record); err != nil {
		return secretKey, errs.Wrap(err)
	}

	return secretKey, err
}

// Get retrieves an access grant and secret key from the key/value store, looked up by the
// hash of the access key and then decrypted.
func (db *Database) Get(ctx context.Context, accessKeyID EncryptionKey) (accessGrant string, public bool, secretKey SecretKey, err error) {
	defer mon.Task()(&ctx)(&err)

	record, err := db.kv.Get(ctx, accessKeyID.Hash())
	if err != nil {
		return "", false, secretKey, errs.Wrap(err)
	} else if record == nil {
		return "", false, secretKey, NotFound.New("key hash: %x", accessKeyID.Hash())
	}

	storjKey := accessKeyID.ToStorjKey()
	// note that we currently always use the same nonce here - all zero's for secret keys
	sk, err := encryption.Decrypt(record.EncryptedSecretKey, storj.EncAESGCM, &storjKey, &storj.Nonce{})
	if err != nil {
		return "", false, secretKey, errs.Wrap(err)
	}
	copy(secretKey[:], sk)
	// note that we currently always use the same nonce here - one then all zero's for access grants
	ag, err := encryption.Decrypt(record.EncryptedAccessGrant, storj.EncAESGCM, &storjKey, &storj.Nonce{1})
	if err != nil {
		return "", false, secretKey, errs.Wrap(err)
	}

	// log satelliteAddress so we can cross reference if we're actively using the distributed db "globally"
	if grant, err := grant.ParseAccess(string(ag)); err == nil {
		mon.Event("as_region_use_get", monkit.NewSeriesTag("satellite", grant.SatelliteAddress))
	}

	return string(ag), record.Public, secretKey, nil
}

// DeleteUnused deletes expired and invalid records from the key/value store and
// returns any error encountered.
func (db *Database) DeleteUnused(ctx context.Context, asOfSystemInterval time.Duration, selectSize, deleteSize int) (count, rounds int64, deletesPerHead map[string]int64, err error) {
	defer mon.Task()(&ctx)(&err)

	count, rounds, deletesPerHead, err = db.kv.DeleteUnused(ctx, asOfSystemInterval, selectSize, deleteSize)

	return count, rounds, deletesPerHead, errs.Wrap(err)
}

// PingDB attempts to do a DB roundtrip. If it can't it will return an error.
func (db *Database) PingDB(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	return errs.Wrap(db.kv.PingDB(ctx))
}

// apiKeyExpiration returns the expiration time of apiKey, and any error
// encountered.
//
// TODO: we should expose this functionality in the API Key type natively.
func apiKeyExpiration(apiKey *macaroon.APIKey) (*time.Time, error) {
	mac, err := macaroon.ParseMacaroon(apiKey.SerializeRaw())
	if err != nil {
		return nil, err
	}

	var expiration *time.Time
	for _, cavbuf := range mac.Caveats() {
		var cav macaroon.Caveat
		err := pb.Unmarshal(cavbuf, &cav)
		if err != nil {
			return nil, err
		}
		if cav.NotAfter != nil {
			cavExpiration := *cav.NotAfter
			if expiration == nil || expiration.After(cavExpiration) {
				expiration = &cavExpiration
			}
		}
	}

	return expiration, nil
}
