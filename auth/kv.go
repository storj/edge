// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package auth

import (
	"context"
)

// Record is a key/value store record.
type Record struct {
	SatelliteAddress     string
	MacaroonHead         []byte // 32 bytes probably
	EncryptedSecretKey   []byte
	EncryptedAccessGrant []byte
}

// KeyHash is the key portion of the key/value store.
type KeyHash [32]byte

// KV is an abstract key/value store of KeyHash to Records.
type KV interface {
	// Put stores the record in the key/value store.
	// It is an error if the key already exists.
	Put(ctx context.Context, keyHash KeyHash, record *Record) (err error)

	// Get retrieves the record from the key/value store.
	// It returns nil if the key does not exist.
	Get(ctx context.Context, keyHash KeyHash) (record *Record, err error)

	// Delete removes the record from the key/value store.
	// It is not an error if the key does not exist.
	Delete(ctx context.Context, keyHash KeyHash) error
}
