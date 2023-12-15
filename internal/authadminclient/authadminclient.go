// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package authadminclient

import (
	"context"
	"encoding/hex"

	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/base58"
	"storj.io/common/encryption"
	"storj.io/common/grant"
	"storj.io/common/storj"
	"storj.io/edge/internal/authadminclient/badgerauth"
	"storj.io/edge/pkg/auth/authdb"
)

// Error is a class of auth admin client errors.
var Error = errs.Class("auth admin client")

// Client is a client for managing auth records.
type Client struct {
	log    *zap.Logger
	admin  authdb.StorageAdmin
	config Config
}

// Record is a representation of pb.Record for display purposes.
type Record struct {
	*authdb.FullRecord
	DecryptedAccessGrant string `json:"decrypted_access_grant,omitempty"`
	MacaroonHeadHex      string `json:"macaroon_head_hex,omitempty"`
	APIKey               string `json:"api_key,omitempty"`
}

func (r *Record) updateFromAuthDB(dbRecord *authdb.FullRecord, encKey authdb.EncryptionKey) error {
	r.FullRecord = dbRecord
	if encKey != (authdb.EncryptionKey{}) {
		storjKey := encKey.ToStorjKey()
		// note that we currently always use the same nonce here - one then all zero's for access grants
		data, err := encryption.Decrypt(dbRecord.EncryptedAccessGrant, storj.EncAESGCM, &storjKey, &storj.Nonce{1})
		if err != nil {
			return errs.New("decrypt access grant: %w", err)
		}
		r.DecryptedAccessGrant = string(data)
		ag, err := grant.ParseAccess(r.DecryptedAccessGrant)
		if err != nil {
			return errs.New("parse access: %w", err)
		}
		r.APIKey = ag.APIKey.Serialize()
	}
	r.MacaroonHeadHex = hex.EncodeToString(r.MacaroonHead)
	return nil
}

// Config configures Client.
type Config struct {
	Badger badgerauth.Config
}

// Open returns an initialized Client connected to the configured badgerauth database.
func Open(ctx context.Context, config Config, log *zap.Logger) (*Client, error) {
	client := &Client{config: config, log: log}

	if len(config.Badger.NodeAddresses) > 0 {
		badger, err := badgerauth.Open(ctx, log, config.Badger)
		if err != nil {
			return nil, err
		}
		client.admin = badger
	}

	return client, nil
}

// Close closes the client's database connection.
func (c *Client) Close() error {
	return Error.Wrap(c.admin.Close())
}

// Get returns a record.
func (c *Client) Get(ctx context.Context, encodedKey string) (record Record, err error) {
	if c.admin == nil {
		return record, Error.New("database isn't configured")
	}

	key, err := keyFromInput(encodedKey)
	if err != nil {
		return record, Error.New("key from input: %w", err)
	}

	resp, err := c.admin.GetFullRecord(ctx, key.hash)
	if err != nil {
		return record, Error.New("get record: %w", err)
	}
	if resp == nil {
		return record, Error.New("key %q does not exist", encodedKey)
	}
	if err = record.updateFromAuthDB(resp, key.encKey); err != nil {
		return record, Error.New("update from auth db: %w", err)
	}

	return record, nil
}

// Invalidate invalidates a record.
func (c *Client) Invalidate(ctx context.Context, encodedKey, reason string) error {
	return c.withDB(ctx, "invalidate", encodedKey, func(ctx context.Context, keyInfo parsedKey, db authdb.StorageAdmin) error {
		return db.Invalidate(ctx, keyInfo.hash, reason)
	})
}

// Unpublish unpublishes a record.
func (c *Client) Unpublish(ctx context.Context, encodedKey string) error {
	return c.withDB(ctx, "unpublish", encodedKey, func(ctx context.Context, keyInfo parsedKey, db authdb.StorageAdmin) error {
		return db.Unpublish(ctx, keyInfo.hash)
	})
}

// Delete deletes a record.
func (c *Client) Delete(ctx context.Context, encodedKey string) error {
	return c.withDB(ctx, "delete", encodedKey, func(ctx context.Context, keyInfo parsedKey, db authdb.StorageAdmin) error {
		return db.Delete(ctx, keyInfo.hash)
	})
}

func (c *Client) withDB(
	ctx context.Context,
	action string,
	encodedKey string,
	fn func(ctx context.Context, key parsedKey, db authdb.StorageAdmin) error,
) error {
	if c.admin == nil {
		return Error.New("database isn't configured")
	}

	keyInfo, err := keyFromInput(encodedKey)
	if err != nil {
		return Error.New("key from input: %w", err)
	}

	if err := fn(ctx, keyInfo, c.admin); err != nil {
		return Error.New("%s record: %w", action, err)
	}

	return nil
}

// Resolve resolves an encryption key or access grant to a record. This is
// useful if input key could be either an encryption key for an authservice
// record, a hash of the encryption key, or an access grant.
//
// Linksharing links support both access keys and access grants, so this is
// useful to look up details for either case.
//
// Note that various fields on pb.Record are not set if resolving an access
// grant, such as EncryptedAccessGrant, and ExpiresAtUnix.
func (c *Client) Resolve(ctx context.Context, encodedKey string) (record Record, err error) {
	switch {
	case len(encodedKey) == authdb.EncKeySizeEncoded || len(encodedKey) == authdb.KeyHashSizeEncoded:
		return c.Get(ctx, encodedKey)
	case isAccessGrant(encodedKey):
		accessGrant, err := grant.ParseAccess(encodedKey)
		if err != nil {
			return record, err
		}
		// linksharing links can contain the access grant directly. While it's
		// not commonly done this way, we handle that case by building an auth
		// record directly.
		return Record{
			FullRecord: &authdb.FullRecord{
				Record: authdb.Record{
					SatelliteAddress: accessGrant.SatelliteAddress,
					MacaroonHead:     accessGrant.APIKey.Head(),
				},
			},
			DecryptedAccessGrant: encodedKey,
			MacaroonHeadHex:      hex.EncodeToString(accessGrant.APIKey.Head()),
			APIKey:               accessGrant.APIKey.Serialize(),
		}, nil
	default:
		return record, errs.New("unknown key value %q", encodedKey)
	}
}

func isAccessGrant(key string) bool {
	_, version, err := base58.CheckDecode(key)
	return err == nil && version == 0
}

type parsedKey struct {
	hash   authdb.KeyHash
	encKey authdb.EncryptionKey
}

func keyFromInput(input string) (info parsedKey, err error) {
	switch len(input) {
	case authdb.KeyHashSizeEncoded:
		if err := info.hash.FromHex(input); err != nil {
			return info, errs.New("hex decode: %w", err)
		}
		return info, nil
	case authdb.EncKeySizeEncoded:
		if err := info.encKey.FromBase32(input); err != nil {
			return info, errs.New("base32 decode: %w", err)
		}
		info.hash = info.encKey.Hash()
		return info, nil
	default:
		return info, errs.New("unknown key input length: %d", len(input))
	}
}
