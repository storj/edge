// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauth

import (
	"context"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/rpc/rpcstatus"
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
}

// Node is distributed auth storage node that wraps DB with machinery to
// replicate records from and to other nodes.
type Node struct {
	db *DB

	config Config
}

// Below is a compile-time check ensuring Node implements the
// DRPCReplicationServiceServer interface.
var _ pb.DRPCReplicationServiceServer = (*Node)(nil)

// New constructs new Node.
func New(log *zap.Logger, config Config) (*Node, error) {
	db, err := OpenDB(log, config)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return &Node{
		db:     db,
		config: config,
	}, nil
}

// UnderlyingDB returns underlying DB.
func (n *Node) UnderlyingDB() *DB {
	return n.db
}

// Replicate implements a node's ability to ship its replication log/records to
// another node. It responds with RPC errors only.
func (n *Node) Replicate(ctx context.Context, req *pb.ReplicationRequest) (*pb.ReplicationResponse, error) {
	var response pb.ReplicationResponse

	for _, reqEntry := range req.Entries {
		var id NodeID

		if err := id.SetBytes(reqEntry.NodeId); err != nil {
			return nil, rpcstatus.Error(rpcstatus.InvalidArgument, err.Error())
		}

		entries, err := n.db.findResponseEntries(id, Clock(reqEntry.Clock))
		if err != nil {
			return nil, rpcstatus.Error(rpcstatus.Internal, err.Error())
		}

		response.Entries = append(response.Entries, entries...)
	}

	return &response, nil
}

// Close releases underlying resources.
func (n *Node) Close() error {
	return n.db.Close()
}
