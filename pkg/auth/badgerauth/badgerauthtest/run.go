// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauthtest

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"golang.org/x/sync/errgroup"

	"storj.io/common/errs2"
	"storj.io/common/testcontext"
	"storj.io/gateway-mt/pkg/auth/badgerauth"
)

// RunSingleNode tests against a single node cluster of badgerauth.
func RunSingleNode(t *testing.T, config badgerauth.Config, fn func(ctx *testcontext.Context, t *testing.T, log *zap.Logger, node *badgerauth.Node)) {
	t.Parallel()

	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	setConfigDefaults(&config)

	log := zaptest.NewLogger(t).Named("badgerauth")
	defer ctx.Check(log.Sync)

	node, err := badgerauth.New(log, config)
	require.NoError(t, err)
	defer ctx.Check(node.Close)

	require.NoError(t, node.UnderlyingDB().PingDB(ctx), "PingDB")

	nodectx, nodecancel := context.WithCancel(ctx)
	var g errgroup.Group
	g.Go(func() error { return node.Run(nodectx) })
	defer ctx.Check(func() error {
		nodecancel()
		return errs2.IgnoreCanceled(g.Wait())
	})

	fn(ctx, t, log, node)
}

// Cluster represents a collection of badgerauth nodes.
type Cluster struct {
	Nodes []*badgerauth.Node
}

// Addresses returns a slice of all cluster node addresses.
func (c *Cluster) Addresses() (addresses []string) {
	for _, node := range c.Nodes {
		addresses = append(addresses, node.Address())
	}
	return addresses
}

// ClusterConfig is used for configuring the cluster.
type ClusterConfig struct {
	NodeCount int
	Defaults  badgerauth.Config

	ReconfigureNode func(index int, config *badgerauth.Config)
}

// RunCluster tests against a multinode cluster of badgerauth.
func RunCluster(t *testing.T, c ClusterConfig, fn func(ctx *testcontext.Context, t *testing.T, cluster *Cluster)) {
	t.Parallel()

	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	log := zaptest.NewLogger(t).Named("badgerauth")
	defer ctx.Check(log.Sync)

	var nodes []*badgerauth.Node
	defer func() {
		for _, node := range nodes {
			ctx.Check(node.Close)
		}
	}()

	for i := 0; i < c.NodeCount; i++ {
		name := strconv.Itoa(i)
		log := log.Named(name)

		config := c.Defaults
		if c.ReconfigureNode != nil {
			c.ReconfigureNode(i, &config)
		}
		require.NoError(t, config.ID.Set(name))
		setConfigDefaults(&config)

		node, err := badgerauth.New(log, config)
		require.NoError(t, err)

		require.NoError(t, node.UnderlyingDB().PingDB(ctx), "PingDB")

		nodes = append(nodes, node)
	}

	for _, node := range nodes {
		addresses := []string{}
		for _, peer := range nodes {
			if peer == node {
				continue
			}
			addresses = append(addresses, peer.Address())
		}
		node.TestingSetJoin(addresses)
	}

	nodectx, nodecancel := context.WithCancel(ctx)

	var g errgroup.Group
	for _, node := range nodes {
		node := node
		g.Go(func() error {
			return errs2.IgnoreCanceled(node.Run(nodectx))
		})
	}

	defer ctx.Check(func() error {
		nodecancel()
		return g.Wait()
	})

	fn(ctx, t, &Cluster{
		Nodes: nodes,
	})
}

func setConfigDefaults(config *badgerauth.Config) {
	config.FirstStart = true

	if config.Address == "" {
		config.Address = "127.0.0.1:0"
	}
	if config.CertsDir == "" {
		config.InsecureDisableTLS = true
	}

	if config.ReplicationInterval == 0 {
		config.ReplicationInterval = 5 * time.Second
	}
	if config.ReplicationLimit == 0 {
		config.ReplicationLimit = 1000
	}

	if config.ConflictBackoff.Max == 0 {
		config.ConflictBackoff.Max = 5 * time.Minute
	}
	if config.ConflictBackoff.Min == 0 {
		config.ConflictBackoff.Min = 100 * time.Millisecond
	}

	if config.Backup.Interval == 0 {
		config.Backup.Interval = time.Hour
	}
}
