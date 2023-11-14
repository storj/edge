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

// Record holds encrypted credentials alongside metadata.
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

// KeyHash is the key under which Records are saved.
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

// Storage is meant to be the storage backend for Auth Service's database, with
// the ability to store and retrieve records saved under key hashes.
type Storage interface {
	// Put stores the record.
	// It is an error if the key already exists.
	Put(ctx context.Context, keyHash KeyHash, record *Record) (err error)

	// Get retrieves the record.
	// It returns (nil, nil) if the key does not exist.
	// If the record is invalid, the error contains why.
	Get(ctx context.Context, keyHash KeyHash) (record *Record, err error)

	// HealthCheck ensures the storage backend works and returns an error
	// otherwise.
	HealthCheck(ctx context.Context) error

	// Run runs the storage backend.
	Run(ctx context.Context) error

	// Close closes the storage backend.
	Close() error
}
