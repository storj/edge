// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package authadminclient

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"log"
	"net"
	"strings"
	"time"

	"github.com/zeebo/errs"

	"storj.io/common/base58"
	"storj.io/common/encryption"
	"storj.io/common/errs2"
	"storj.io/common/grant"
	"storj.io/common/storj"
	"storj.io/drpc/drpcconn"
	"storj.io/edge/pkg/auth/authdb"
	"storj.io/edge/pkg/auth/badgerauth"
	"storj.io/edge/pkg/auth/badgerauth/pb"
)

// Error is a class of auth admin client errors.
var Error = errs.Class("auth admin client")

// Client is a client for managing auth records.
type Client struct {
	log    *log.Logger
	config Config
}

// Record is a representation of pb.Record for display purposes.
type Record struct {
	*pb.Record
	DecryptedAccessGrant string `json:"decrypted_access_grant,omitempty"`
	MacaroonHeadHex      string `json:"macaroon_head_hex,omitempty"`
	APIKey               string `json:"api_key,omitempty"`
}

func (r *Record) updateFromProto(pr *pb.Record, encKey authdb.EncryptionKey) error {
	r.Record = pr
	if encKey != (authdb.EncryptionKey{}) {
		storjKey := encKey.ToStorjKey()
		// note that we currently always use the same nonce here - one then all zero's for access grants
		data, err := encryption.Decrypt(pr.EncryptedAccessGrant, storj.EncAESGCM, &storjKey, &storj.Nonce{1})
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
	NodeAddresses []string `user:"true" help:"comma delimited list of node addresses"`
	CertsDir      string   `user:"true" help:"directory for certificates for authentication"`

	// InsecureDisableTLS allows disabling tls for testing.
	InsecureDisableTLS bool `internal:"true"`
}

// New returns a new Client.
func New(config Config, log *log.Logger) *Client {
	return &Client{config: config, log: log}
}

// Get gets a record from the first configured node address.
func (c *Client) Get(ctx context.Context, encodedKey string) (record Record, err error) {
	keyHash, encKey, err := keyFromInput(encodedKey)
	if err != nil {
		return record, Error.New("key from input: %w", err)
	}

	var addresses []string
	if len(c.config.NodeAddresses) > 0 {
		addresses = c.config.NodeAddresses[:1]
	}

	return record, Error.Wrap(c.withReplicationClient(ctx, addresses, func(ctx context.Context, client pb.DRPCReplicationServiceClient) error {
		resp, err := client.Peek(ctx, &pb.PeekRequest{EncryptionKeyHash: keyHash.Bytes()})
		if err != nil {
			return errs.New("peek record: %w", err)
		}

		if err = record.updateFromProto(resp.Record, encKey); err != nil {
			return errs.New("update from proto: %w", err)
		}

		return nil
	}))
}

// Invalidate invalidates a record on all configured node addresses.
func (c *Client) Invalidate(ctx context.Context, encodedKey, reason string) error {
	keyHash, _, err := keyFromInput(encodedKey)
	if err != nil {
		return Error.New("key from input: %w", err)
	}

	return Error.Wrap(c.withAdminClient(ctx, c.config.NodeAddresses, func(ctx context.Context, client pb.DRPCAdminServiceClient) error {
		_, err := client.InvalidateRecord(ctx, &pb.InvalidateRecordRequest{
			Key:    keyHash.Bytes(),
			Reason: reason,
		})
		if err != nil {
			return errs.New("invalidate record: %w", err)
		}
		return nil
	}))
}

// Unpublish unpublishes a record on all configured node addresses.
func (c *Client) Unpublish(ctx context.Context, encodedKey string) error {
	keyHash, _, err := keyFromInput(encodedKey)
	if err != nil {
		return Error.New("key from input: %w", err)
	}

	return Error.Wrap(c.withAdminClient(ctx, c.config.NodeAddresses, func(ctx context.Context, client pb.DRPCAdminServiceClient) error {
		_, err := client.UnpublishRecord(ctx, &pb.UnpublishRecordRequest{Key: keyHash.Bytes()})
		if err != nil {
			return errs.New("unpublish record: %w", err)
		}
		return nil
	}))
}

// Delete deletes a record on all configured node addresses.
func (c *Client) Delete(ctx context.Context, encodedKey string) error {
	keyHash, _, err := keyFromInput(encodedKey)
	if err != nil {
		return Error.New("key from input: %w", err)
	}

	return Error.Wrap(c.withAdminClient(ctx, c.config.NodeAddresses, func(ctx context.Context, client pb.DRPCAdminServiceClient) error {
		_, err := client.DeleteRecord(ctx, &pb.DeleteRecordRequest{Key: keyHash.Bytes()})
		if err != nil {
			return errs.New("delete record: %w", err)
		}
		return nil
	}))
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
			Record: &pb.Record{
				SatelliteAddress: accessGrant.SatelliteAddress,
				MacaroonHead:     accessGrant.APIKey.Head(),
			},
			DecryptedAccessGrant: encodedKey,
			MacaroonHeadHex:      hex.EncodeToString(accessGrant.APIKey.Head()),
			APIKey:               accessGrant.APIKey.Serialize(),
		}, nil
	default:
		return record, errs.New("unknown key value %q", encodedKey)
	}
}

// withAdminClient runs fn concurrently on given node addresses.
func (c *Client) withAdminClient(ctx context.Context, addresses []string, fn func(ctx context.Context, client pb.DRPCAdminServiceClient) error) error {
	if len(addresses) == 0 {
		return errs.New("node addresses unspecified")
	}
	var group errs2.Group
	for _, address := range addresses {
		address := address
		group.Go(func() error {
			conn, err := dialAddress(ctx, address, c.config.CertsDir, c.config.InsecureDisableTLS, c.log)
			if err != nil {
				return err
			}
			defer func() { _ = conn.Close() }()
			start := time.Now()
			if err := fn(ctx, pb.NewDRPCAdminServiceClient(drpcconn.New(conn))); err != nil {
				return errs.New("node %q request failed: %w", address, err)
			}
			c.log.Println("received successful response from", address, "(time taken:", time.Since(start), ")")
			return nil
		})
	}
	return errs.Combine(group.Wait()...)
}

// withReplicationClient runs fn sequentially on given node addresses.
func (c *Client) withReplicationClient(ctx context.Context, addresses []string, fn func(ctx context.Context, client pb.DRPCReplicationServiceClient) error) error {
	if len(addresses) == 0 {
		return errs.New("node addresses unspecified")
	}
	for _, address := range addresses {
		conn, err := dialAddress(ctx, address, c.config.CertsDir, c.config.InsecureDisableTLS, c.log)
		if err != nil {
			return err
		}
		defer func() { _ = conn.Close() }()
		start := time.Now()
		if err := fn(ctx, pb.NewDRPCReplicationServiceClient(drpcconn.New(conn))); err != nil {
			return errs.New("node %q request failed: %w", address, err)
		}
		c.log.Println("received successful response from", address, "(time taken:", time.Since(start), ")")
	}
	return nil
}

func isAccessGrant(key string) bool {
	_, version, err := base58.CheckDecode(key)
	return err == nil && version == 0
}

func dialAddress(ctx context.Context, address, certsDir string, insecureDisableTLS bool, log *log.Logger) (net.Conn, error) {
	var tlsConfig *tls.Config
	if !insecureDisableTLS {
		opts := badgerauth.TLSOptions{CertsDir: certsDir}
		tlsCfg, err := opts.Load()
		if err != nil {
			return nil, errs.New("failed to load tls config: %w", err)
		}
		tlsConfig = tlsCfg
	}

	var host string

	// allow specifying host mapping, e.g. "1.2.3.4:20004=authnode-dc1-app1"
	// but fallback to a single address if a single address given.
	parts := strings.Split(address, "=")
	switch len(parts) {
	case 1:
		address = parts[0]
	case 2:
		address = parts[0]
		host = parts[1]
	default:
		return nil, errs.New("invalid address format: %q", address)
	}

	var dialer interface {
		DialContext(context.Context, string, string) (net.Conn, error)
	}
	if tlsConfig != nil {
		tlsConfig.ServerName = host
		dialer = &tls.Dialer{Config: tlsConfig}
	} else {
		dialer = &net.Dialer{}
	}
	log.Println("connecting to", address)

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, errs.New("dial node %q failed: %w", address, err)
	}
	log.Println("connection established to", address, "(time taken:", time.Since(start), ")")

	return conn, nil
}

func keyFromInput(input string) (keyHash authdb.KeyHash, encKey authdb.EncryptionKey, err error) {
	switch len(input) {
	case authdb.KeyHashSizeEncoded:
		if err := keyHash.FromHex(input); err != nil {
			return keyHash, encKey, errs.New("hex decode: %w", err)
		}
		return keyHash, encKey, nil
	case authdb.EncKeySizeEncoded:
		if err := encKey.FromBase32(input); err != nil {
			return keyHash, encKey, errs.New("base32 decode: %w", err)
		}
		return encKey.Hash(), encKey, nil
	default:
		return keyHash, encKey, errs.New("unknown key input length: %d", len(input))
	}
}
