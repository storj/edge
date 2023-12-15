// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauth

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"time"

	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/errs2"
	"storj.io/common/rpc/rpcstatus"
	"storj.io/drpc"
	"storj.io/drpc/drpcconn"
	"storj.io/edge/pkg/auth/authdb"
	"storj.io/edge/pkg/auth/badgerauth"
	"storj.io/edge/pkg/auth/badgerauth/pb"
)

var (
	// Ensure Client implements authdb.StorageAdmin.
	_ authdb.StorageAdmin = (*Client)(nil)

	// Error is a class for badgerauth admin client errors.
	Error = errs.Class("badgerauth admin client")
)

// Config contains configuration options for a badgerauth admin client.
type Config struct {
	NodeAddresses []string `user:"true" help:"comma delimited list of node addresses"`
	CertsDir      string   `user:"true" help:"directory for certificates for authentication"`

	// InsecureDisableTLS allows disabling tls for testing.
	InsecureDisableTLS bool `internal:"true"`
}

// Client allows for performing administrative actions on a badgerauth database.
type Client struct {
	log         *zap.Logger
	config      Config
	nodeClients map[string]*badgerAuthDRPCClient
}

// Open returns a new badgerauth admin client connected to the configured nodes.
func Open(ctx context.Context, log *zap.Logger, config Config) (*Client, error) {
	if len(config.NodeAddresses) == 0 {
		return nil, Error.New("no node addresses configured")
	}

	client := &Client{
		log:         log,
		config:      config,
		nodeClients: make(map[string]*badgerAuthDRPCClient, len(config.NodeAddresses)),
	}

	for _, address := range config.NodeAddresses {
		conn, err := client.dialAddress(ctx, address)
		if err != nil {
			return nil, errs.Combine(err, client.Close())
		}
		client.nodeClients[address] = newBadgerAuthDRPCClient(drpcconn.New(conn))
	}

	return client, nil
}

// Close closes the connection to the configured nodes.
func (c *Client) Close() error {
	return c.withNodes(context.Background(), func(ctx context.Context, client *badgerAuthDRPCClient) error {
		return client.DRPCConn().Close()
	})
}

// Put stores the record in all configured nodes.
func (c *Client) Put(ctx context.Context, keyHash authdb.KeyHash, record *authdb.Record) (err error) {
	return Error.New("not implemented")
}

// Get retrieves the record. It returns (nil, nil) if the key does not exist. If the record is invalid, the error contains why.
func (c *Client) Get(ctx context.Context, keyHash authdb.KeyHash) (record *authdb.Record, err error) {
	r, err := c.GetFullRecord(ctx, keyHash)
	if err != nil {
		return nil, err
	}
	if r.IsInvalid() {
		return nil, Error.Wrap(authdb.Invalid.New("%s", r.InvalidationReason))
	}
	return &r.Record, nil
}

// HealthCheck ensures all configured nodes can be contacted and returns an error otherwise.
func (c *Client) HealthCheck(ctx context.Context) error {
	return c.withNodes(ctx, func(ctx context.Context, client *badgerAuthDRPCClient) error {
		_, err := client.replication.Ping(ctx, &pb.PingRequest{})
		return err
	})
}

// Run is a no-op for implementing authdb.Storage. Open should be used instead to run the client.
func (c *Client) Run(ctx context.Context) error {
	return nil
}

// GetFullRecord retrieves a record with invalidation information from the first configured node address.
func (c *Client) GetFullRecord(ctx context.Context, keyHash authdb.KeyHash) (*authdb.FullRecord, error) {
	if len(c.config.NodeAddresses) == 0 {
		return nil, Error.New("no node addresses configured")
	}

	address := c.config.NodeAddresses[0]
	nodeClient := c.nodeClients[address]

	start := time.Now()
	r, err := nodeClient.replication.Peek(ctx, &pb.PeekRequest{EncryptionKeyHash: keyHash.Bytes()})
	if err != nil {
		if errs2.IsRPC(err, rpcstatus.NotFound) {
			return nil, nil
		}
		return nil, Error.New("node %q request failed: %w", address, err)
	}
	c.log.Info("response received successfully", zap.String("address", address), zap.Duration("elapsed", time.Since(start)))

	record := &authdb.FullRecord{
		Record: authdb.Record{
			SatelliteAddress:     r.Record.SatelliteAddress,
			MacaroonHead:         r.Record.MacaroonHead,
			EncryptedSecretKey:   r.Record.EncryptedSecretKey,
			EncryptedAccessGrant: r.Record.EncryptedAccessGrant,
			Public:               r.Record.Public,
		},
		CreatedAt:          time.Unix(r.Record.CreatedAtUnix, 0),
		InvalidationReason: r.Record.InvalidationReason,
	}
	if r.Record.ExpiresAtUnix != 0 {
		expiresAt := time.Unix(r.Record.ExpiresAtUnix, 0)
		record.ExpiresAt = &expiresAt
	}
	if r.Record.InvalidatedAtUnix != 0 {
		record.InvalidatedAt = time.Unix(r.Record.InvalidatedAtUnix, 0)
	}

	return record, nil
}

// Invalidate invalidates a record on all configured node addresses.
func (c *Client) Invalidate(ctx context.Context, keyHash authdb.KeyHash, reason string) error {
	return c.withNodes(ctx, func(ctx context.Context, client *badgerAuthDRPCClient) error {
		_, err := client.admin.InvalidateRecord(ctx, &pb.InvalidateRecordRequest{
			Key:    keyHash.Bytes(),
			Reason: reason,
		})
		return err
	})
}

// Unpublish unpublishes a record on all configured node addresses.
func (c *Client) Unpublish(ctx context.Context, keyHash authdb.KeyHash) error {
	return c.withNodes(ctx, func(ctx context.Context, client *badgerAuthDRPCClient) error {
		_, err := client.admin.UnpublishRecord(ctx, &pb.UnpublishRecordRequest{Key: keyHash.Bytes()})
		return err
	})
}

// Delete deletes a record on all configured node addresses.
func (c *Client) Delete(ctx context.Context, keyHash authdb.KeyHash) error {
	return c.withNodes(ctx, func(ctx context.Context, client *badgerAuthDRPCClient) error {
		_, err := client.admin.DeleteRecord(ctx, &pb.DeleteRecordRequest{Key: keyHash.Bytes()})
		return err
	})
}

type badgerAuthDRPCClient struct {
	replication pb.DRPCReplicationServiceClient
	admin       pb.DRPCAdminServiceClient
}

// DRPCConn returns the DRPC connection.
func (c *badgerAuthDRPCClient) DRPCConn() drpc.Conn {
	return c.replication.DRPCConn()
}

func newBadgerAuthDRPCClient(conn drpc.Conn) *badgerAuthDRPCClient {
	return &badgerAuthDRPCClient{
		replication: pb.NewDRPCReplicationServiceClient(conn),
		admin:       pb.NewDRPCAdminServiceClient(conn),
	}
}

// withNodes runs fn concurrently on all configured node addresses.
func (c *Client) withNodes(ctx context.Context, fn func(ctx context.Context, client *badgerAuthDRPCClient) error) error {
	if len(c.config.NodeAddresses) == 0 {
		return Error.New("no node addresses configured")
	}

	var group errs2.Group
	for address, nodeClient := range c.nodeClients {
		address, nodeClient := address, nodeClient
		group.Go(func() error {
			start := time.Now()
			if err := fn(ctx, nodeClient); err != nil {
				return errs.New("node %q request failed: %w", address, err)
			}
			c.log.Info("response received successfully", zap.String("address", address), zap.Duration("elapsed", time.Since(start)))
			return nil
		})
	}
	return Error.Wrap(errs.Combine(group.Wait()...))
}

func (c *Client) dialAddress(ctx context.Context, address string) (net.Conn, error) {
	var tlsConfig *tls.Config
	if !c.config.InsecureDisableTLS {
		opts := badgerauth.TLSOptions{CertsDir: c.config.CertsDir}
		tlsCfg, err := opts.Load()
		if err != nil {
			return nil, Error.New("failed to load tls config: %w", err)
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
		return nil, Error.New("invalid address format: %q", address)
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
	c.log.Info("connecting to node", zap.String("address", address))

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, Error.New("dial node %q failed: %w", address, err)
	}
	c.log.Info("connection established", zap.String("address", address), zap.Duration("elapsed", time.Since(start)))

	return conn, nil
}
