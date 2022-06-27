// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package authadminclient

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/zeebo/errs"

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
	config Config
}

// Record is a representation of pb.Record for display purposes.
type Record struct {
	*pb.Record
	DecryptedAccessGrant string `json:"decrypted_access_grant,omitempty"`
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
func New(config Config) *AuthAdminClient {
	return &AuthAdminClient{config: config}
}

// Get gets a record.
func (c *AuthAdminClient) Get(ctx context.Context, encodedKey string) (*Record, error) {
	keyHash, encKey, err := keyFromInput(encodedKey)
	if err != nil {
		return nil, Error.New("key from input: %w", err)
	}

	var record Record

	return &record, Error.Wrap(c.withServiceClient(ctx, func(ctx context.Context, client pb.DRPCAdminServiceClient) error {
		resp, err := client.GetRecord(ctx, &pb.GetRecordRequest{Key: keyHash.Bytes()})
		if err != nil {
			return errs.New("get record: %w", err)
		}

		return record.updateFromProto(resp.Record, encKey)
	}))
}

// Invalidate invalidates a record.
func (c *AuthAdminClient) Invalidate(ctx context.Context, encodedKey, reason string) error {
	keyHash, _, err := keyFromInput(encodedKey)
	if err != nil {
		return Error.New("key from input: %w", err)
	}

	return Error.Wrap(c.withServiceClient(ctx, func(ctx context.Context, client pb.DRPCAdminServiceClient) error {
		_, err = client.InvalidateRecord(ctx, &pb.InvalidateRecordRequest{
			Key:    keyHash.Bytes(),
			Reason: reason,
		})
		if err != nil {
			return errs.New("invalidate record: %w", err)
		}
		return nil
	}))
}

// Unpublish unpublishes a record.
func (c *AuthAdminClient) Unpublish(ctx context.Context, encodedKey string) error {
	keyHash, _, err := keyFromInput(encodedKey)
	if err != nil {
		return Error.New("key from input: %w", err)
	}

	return Error.Wrap(c.withServiceClient(ctx, func(ctx context.Context, client pb.DRPCAdminServiceClient) error {
		_, err = client.UnpublishRecord(ctx, &pb.UnpublishRecordRequest{Key: keyHash.Bytes()})
		if err != nil {
			return errs.New("unpublish record: %w", err)
		}
		return nil
	}))
}

// Delete deletes a record.
func (c *AuthAdminClient) Delete(ctx context.Context, encodedKey string) error {
	keyHash, _, err := keyFromInput(encodedKey)
	if err != nil {
		return Error.New("key from input: %w", err)
	}

	return Error.Wrap(c.withServiceClient(ctx, func(ctx context.Context, client pb.DRPCAdminServiceClient) error {
		_, err = client.DeleteRecord(ctx, &pb.DeleteRecordRequest{Key: keyHash.Bytes()})
		if err != nil {
			return errs.New("delete record: %w", err)
		}
		return nil
	}))
}

func (c *AuthAdminClient) withServiceClient(ctx context.Context, fn func(ctx context.Context, client pb.DRPCAdminServiceClient) error) error {
	if len(c.config.NodeAddresses) == 0 {
		return errs.New("node addresses unspecified")
	}

	var tlsConfig *tls.Config
	if !c.config.InsecureDisableTLS {
		opts := badgerauth.TLSOptions{CertsDir: c.config.CertsDir}
		tlsCfg, err := opts.Load()
		if err != nil {
			return errs.New("failed to load tls config: %w", err)
		}
		tlsConfig = tlsCfg
	}

	var conns []*drpcconn.Conn
	for _, address := range c.config.NodeAddresses {
		var dialer interface {
			DialContext(context.Context, string, string) (net.Conn, error)
		}
		if tlsConfig != nil {
			dialer = &tls.Dialer{Config: tlsConfig}
		} else {
			dialer = &net.Dialer{}
		}
		rawconn, err := dialer.DialContext(ctx, "tcp", address)
		if err != nil {
			return errs.New("dial failed: %w", err)
		}

		conn := drpcconn.New(rawconn)
		defer func() { _ = rawconn.Close() }()
		conns = append(conns, conn)
	}

	var errlist errs.Group
	for i, conn := range conns {
		if err := fn(ctx, pb.NewDRPCAdminServiceClient(conn)); err != nil {
			errlist.Add(errs.New("node %q request failed: %w", c.config.NodeAddresses[i], err))
		}
	}

	return errlist.Err()
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
