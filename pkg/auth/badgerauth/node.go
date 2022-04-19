// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauth

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"storj.io/common/rpc"
	"storj.io/common/rpc/rpcstatus"
	"storj.io/drpc/drpcmux"
	"storj.io/drpc/drpcserver"
	"storj.io/gateway-mt/pkg/auth/badgerauth/pb"
	"storj.io/gateway-mt/pkg/backoff"
)

var (
	mon = monkit.Package()

	// Error is the default error class for the badgerauth package.
	Error = errs.Class("badgerauth")
)

// Config provides options for creating a Node.
type Config struct {
	ID NodeID `user:"true" help:"unique identifier for the node" default:""`

	// Path is where to store data. Empty means in memory.
	Path string `user:"true" help:"path where to store data" default:""`

	Address  string   `user:"true" help:"address that the node listens on" default:""`
	Join     []string `user:"true" help:"comma delimited list of cluster peers" default:""`
	CertsDir string   `user:"true" help:"directory for certificates for mutual authentication"`

	// ReplicationLimit is per node ID limit of replication response entries to return.
	ReplicationLimit int `user:"true" help:"maximum entries returned in replication response" default:"100"`
	// ConflictBackoff configures retries for conflicting transactions that may
	// occur when Node's underlying database is under heavy load.
	ConflictBackoff backoff.ExponentialBackoff

	// InsecureDisableTLS allows disabling tls for testing.
	InsecureDisableTLS bool `internal:"true"`
}

// Node is distributed auth storage node that wraps DB with machinery to
// replicate records from and to other nodes.
type Node struct {
	db *DB

	config Config

	tls      *tls.Config
	listener net.Listener
	mux      *drpcmux.Mux
	server   *drpcserver.Server
}

// Below is a compile-time check ensuring Node implements the
// DRPCReplicationServiceServer interface.
var _ pb.DRPCReplicationServiceServer = (*Node)(nil)

// New constructs new Node.
func New(log *zap.Logger, config Config) (_ *Node, err error) {
	node := &Node{
		config: config,
		mux:    drpcmux.New(),
	}
	defer func() {
		if err != nil {
			_ = node.Close()
		}
	}()

	node.db, err = OpenDB(log, config)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	if err = pb.DRPCRegisterReplicationService(node.mux, node); err != nil {
		return nil, Error.New("failed to register server: %w", err)
	}

	serverOptions := drpcserver.Options{
		Manager: rpc.NewDefaultManagerOptions(),
	}
	node.server = drpcserver.NewWithOptions(node.mux, serverOptions)

	if !config.InsecureDisableTLS {
		opts := TLSOptions{
			CertsDir: config.CertsDir,
		}
		node.tls, err = opts.Load()
		if err != nil {
			return nil, Error.New("failed to load tls config: %w", err)
		}
	}

	tcpListener, err := net.Listen("tcp", config.Address)
	if err != nil {
		return nil, Error.New("failed to listen on %q: %w", config.Address, err)
	}

	if !config.InsecureDisableTLS {
		node.listener = tls.NewListener(tcpListener, node.tls)
	} else {
		node.listener = tcpListener
	}

	return node, nil
}

// ID returns the configured node id.
func (node *Node) ID() NodeID { return node.config.ID }

// Address returns the server address.
func (node *Node) Address() string {
	return node.listener.Addr().String()
}

// Run runs the server and the associated servers.
func (node *Node) Run(ctx context.Context) error {
	group, ctx := errgroup.WithContext(ctx)
	group.Go(func() error {
		return Error.Wrap(node.server.Serve(ctx, node.listener))
	})
	return Error.Wrap(group.Wait())
}

// Close releases underlying resources.
func (node *Node) Close() error {
	var g errs.Group
	if node.listener != nil {
		// if the server is started, then `server.Serve` automatically closes the listener
		_ = node.listener.Close()
	}
	if node.db != nil {
		g.Add(node.db.Close())
	}
	return Error.Wrap(g.Err())
}

// Ping allows to fetch information about the node.
func (node *Node) Ping(ctx context.Context, req *pb.PingRequest) (*pb.PingResponse, error) {
	return &pb.PingResponse{
		NodeId: node.config.ID.Bytes(),
	}, nil
}

// Replicate implements a node's ability to ship its replication log/records to
// another node. It responds with RPC errors only.
func (node *Node) Replicate(ctx context.Context, req *pb.ReplicationRequest) (*pb.ReplicationResponse, error) {
	var response pb.ReplicationResponse

	for _, reqEntry := range req.Entries {
		var id NodeID

		if err := id.SetBytes(reqEntry.NodeId); err != nil {
			return nil, rpcstatus.Error(rpcstatus.InvalidArgument, err.Error())
		}

		entries, err := node.db.findResponseEntries(id, Clock(reqEntry.Clock))
		if err != nil {
			return nil, rpcstatus.Error(rpcstatus.Internal, err.Error())
		}

		response.Entries = append(response.Entries, entries...)
	}

	return &response, nil
}

// UnderlyingDB returns underlying DB.
func (node *Node) UnderlyingDB() *DB {
	return node.db
}
