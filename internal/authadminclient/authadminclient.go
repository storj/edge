// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package authadminclient

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"log"
	"net"
	"time"

	"github.com/zeebo/errs"
	"golang.org/x/sync/errgroup"

	"storj.io/common/encryption"
	"storj.io/common/grant"
	"storj.io/common/storj"
	"storj.io/drpc/drpcconn"
	"storj.io/gateway-mt/pkg/auth/authdb"
	"storj.io/gateway-mt/pkg/auth/badgerauth"
	"storj.io/gateway-mt/pkg/auth/badgerauth/pb"
)

// Error is a class of auth admin client errors.
var Error = errs.Class("auth admin client")

// AuthAdminClient is a client for managing auth records.
type AuthAdminClient struct {
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

// Config configures AuthAdminClient.
type Config struct {
	NodeAddresses []string `user:"true" help:"comma delimited list of node addresses"`
	CertsDir      string   `user:"true" help:"directory for certificates for authentication"`

	// InsecureDisableTLS allows disabling tls for testing.
	InsecureDisableTLS bool `internal:"true"`
}

// New returns a new AuthAdminClient.
func New(config Config, log *log.Logger) *AuthAdminClient {
	return &AuthAdminClient{config: config, log: log}
}

// Get gets a record from the first configured node address.
func (c *AuthAdminClient) Get(ctx context.Context, encodedKey string) (record *Record, err error) {
	keyHash, encKey, err := keyFromInput(encodedKey)
	if err != nil {
		return nil, Error.New("key from input: %w", err)
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

		record = &Record{}
		if err = record.updateFromProto(resp.Record, encKey); err != nil {
			return errs.New("update from proto: %w", err)
		}

		return nil
	}))
}

// Invalidate invalidates a record on all configured node addresses.
func (c *AuthAdminClient) Invalidate(ctx context.Context, encodedKey, reason string) error {
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
func (c *AuthAdminClient) Unpublish(ctx context.Context, encodedKey string) error {
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
func (c *AuthAdminClient) Delete(ctx context.Context, encodedKey string) error {
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

// withAdminClient runs fn concurrently on given node addresses.
func (c *AuthAdminClient) withAdminClient(ctx context.Context, addresses []string, fn func(ctx context.Context, client pb.DRPCAdminServiceClient) error) error {
	if len(addresses) == 0 {
		return errs.New("node addresses unspecified")
	}
	var group errgroup.Group
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
	return group.Wait()
}

// withReplicationClient runs fn sequentially on given node addresses.
func (c *AuthAdminClient) withReplicationClient(ctx context.Context, addresses []string, fn func(ctx context.Context, client pb.DRPCReplicationServiceClient) error) error {
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

	var dialer interface {
		DialContext(context.Context, string, string) (net.Conn, error)
	}
	if tlsConfig != nil {
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
