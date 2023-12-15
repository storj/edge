// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package authadminclient

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/base58"
	"storj.io/common/encryption"
	"storj.io/common/grant"
	"storj.io/common/storj"
	"storj.io/edge/internal/authadminclient/badgerauth"
	"storj.io/edge/pkg/auth/authdb"
	"storj.io/edge/pkg/auth/spannerauth"
)

// Error is a class of auth admin client errors.
var Error = errs.Class("auth admin client")

// Client is a client for managing auth records.
type Client struct {
	log     *zap.Logger
	spanner authdb.StorageAdmin
	badger  authdb.StorageAdmin
	config  Config
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
	Spanner spannerauth.Config
	Badger  badgerauth.Config
}

// Open returns an initialized Client connected to the configured databases.
func Open(ctx context.Context, config Config, log *zap.Logger) (*Client, error) {
	client := &Client{config: config, log: log}

	if config.Spanner.DatabaseName != "" {
		spanner, err := spannerauth.Open(ctx, log, config.Spanner)
		if err != nil {
			return nil, Error.Wrap(err)
		}
		client.spanner = spanner
	}

	if len(config.Badger.NodeAddresses) > 0 {
		badger, err := badgerauth.Open(ctx, log, config.Badger)
		if err != nil {
			return nil, Error.Wrap(errs.Combine(err, client.Close()))
		}
		client.badger = badger
	}

	return client, nil
}

// Close closes the client's database connections.
func (c *Client) Close() error {
	return Error.Wrap(errs.Combine(c.spanner.Close(), c.badger.Close()))
}

// Get returns a record.
func (c *Client) Get(ctx context.Context, encodedKey string) (record Record, err error) {
	if c.spanner == nil && c.badger == nil {
		return record, Error.New("no databases configured")
	}

	key, err := keyFromInput(encodedKey)
	if err != nil {
		return record, Error.New("key from input: %w", err)
	}

	var spannerResp *authdb.FullRecord
	if c.spanner != nil {
		spannerResp, err = c.spanner.GetFullRecord(ctx, key.hash)
		if err != nil {
			return record, Error.New("get record: %w", err)
		}
		if spannerResp == nil {
			c.log.Warn("record not found", zap.String("key", encodedKey), zap.String("backend", "spanner"))
		}
	}

	var badgerResp *authdb.FullRecord
	if c.badger != nil {
		badgerResp, err = c.badger.GetFullRecord(ctx, key.hash)
		if err != nil {
			return record, Error.New("get record: %w", err)
		}
		if badgerResp == nil {
			c.log.Warn("record not found", zap.String("key", encodedKey), zap.String("backend", "badger"))
		}
	}

	var resp *authdb.FullRecord
	if spannerResp != nil {
		if badgerResp != nil && !spannerResp.EqualWithinDuration(*badgerResp, time.Minute) {
			return record, Error.New("mismatch between spanner and badger records")
		}
		resp = spannerResp
	} else if badgerResp != nil {
		resp = badgerResp
	} else {
		return record, Error.New("key %q does not exist", key)
	}

	if err = record.updateFromAuthDB(resp, key.encKey); err != nil {
		return record, Error.New("update from auth db: %w", err)
	}
	return record, nil
}

// Invalidate invalidates a record on all configured authservice databases.
func (c *Client) Invalidate(ctx context.Context, encodedKey, reason string) error {
	return c.withDBs(ctx, "invalidate", encodedKey, func(ctx context.Context, keyInfo parsedKey, admin authdb.StorageAdmin) error {
		return admin.Invalidate(ctx, keyInfo.hash, reason)
	})
}

// Unpublish unpublishes a record on all configured authservice databases.
func (c *Client) Unpublish(ctx context.Context, encodedKey string) error {
	return c.withDBs(ctx, "unpublish", encodedKey, func(ctx context.Context, keyInfo parsedKey, admin authdb.StorageAdmin) error {
		return admin.Unpublish(ctx, keyInfo.hash)
	})
}

// Delete deletes a record from all configured authservice databases.
func (c *Client) Delete(ctx context.Context, encodedKey string) error {
	return c.withDBs(ctx, "delete", encodedKey, func(ctx context.Context, keyInfo parsedKey, admin authdb.StorageAdmin) error {
		return admin.Delete(ctx, keyInfo.hash)
	})
}

func (c *Client) withDBs(
	ctx context.Context,
	action string,
	encodedKey string,
	fn func(ctx context.Context, key parsedKey, db authdb.StorageAdmin) error,
) error {
	if c.spanner == nil && c.badger == nil {
		return Error.New("no databases configured")
	}

	keyInfo, err := keyFromInput(encodedKey)
	if err != nil {
		return Error.New("key from input: %w", err)
	}

	var errGroup errs.Group
	if c.spanner != nil {
		errGroup.Add(fn(ctx, keyInfo, c.spanner))
	}
	if c.badger != nil {
		errGroup.Add(fn(ctx, keyInfo, c.badger))
	}
	if err := errGroup.Err(); err != nil {
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
