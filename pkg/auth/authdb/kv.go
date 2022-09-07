// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package authdb

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/zeebo/errs"
)

// Invalid is the class of error that is returned for invalid records.
var Invalid = errs.Class("invalid")

// KeyHashError is a class of key hash errors.
var KeyHashError = errs.Class("key hash")

// Record is a key/value store record.
type Record struct {
	SatelliteAddress     string
	MacaroonHead         []byte // 32 bytes probably
	EncryptedSecretKey   []byte
	EncryptedAccessGrant []byte
	ExpiresAt            *time.Time
	Public               bool // if true, knowledge of secret key is not required
}

// KeyHashSizeEncoded is the length of a hex encoded KeyHash.
const KeyHashSizeEncoded = 64

// KeyHash is the key portion of the key/value store.
type KeyHash [32]byte

// SetBytes sets the key hash from bytes.
func (kh *KeyHash) SetBytes(v []byte) error {
	if len(v) > len(KeyHash{}) {
		return KeyHashError.New("v exceeds the acceptable length")
	}
	*kh = KeyHash{}
	copy(kh[:], v)
	return nil
}

// FromHex sets the key hash from a hex encoded string.
func (kh *KeyHash) FromHex(encoded string) error {
	if len(encoded) != KeyHashSizeEncoded {
		return KeyHashError.New("length expected to be %d, was %d", KeyHashSizeEncoded, len(encoded))
	}
	bytes, err := hex.DecodeString(encoded)
	if err != nil {
		return KeyHashError.New("error decoding key hash: %w", err)
	}
	if err := kh.SetBytes(bytes); err != nil {
		return KeyHashError.New("error setting key hash bytes: %w", err)
	}
	return nil
}

// ToHex converts a key hash to a hex encoded string.
func (kh KeyHash) ToHex() string {
	return hex.EncodeToString(kh.Bytes())
}

// Bytes returns the bytes for key hash.
func (kh KeyHash) Bytes() []byte { return kh[:] }

// KV is an abstract key/value store of KeyHash to Records.
type KV interface {
	// Put stores the record in the key/value store.
	// It is an error if the key already exists.
	Put(ctx context.Context, keyHash KeyHash, record *Record) (err error)

	// Get retrieves the record from the key/value store.
	// It returns nil if the key does not exist.
	// If the record is invalid, the error contains why.
	Get(ctx context.Context, keyHash KeyHash) (record *Record, err error)

	// DeleteUnused deletes expired and invalid records from the key/value store
	// and returns any error encountered.
	//
	// Batch deletion and usage of asOfSystemInterval, selectSize and deleteSize
	// parameters depends on the implementation.
	DeleteUnused(ctx context.Context, asOfSystemInterval time.Duration, selectSize, deleteSize int) (count, rounds int64, deletesPerHead map[string]int64, err error)

	// PingDB attempts to do a DB roundtrip. If it can't it will return an
	// error.
	PingDB(ctx context.Context) error

	// Run runs the server and the associated servers
	Run(ctx context.Context) error

	// Close closes the database.
	Close() error
}
