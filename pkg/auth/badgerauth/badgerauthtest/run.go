// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauthtest

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	"golang.org/x/sync/errgroup"

	"storj.io/common/errs2"
	"storj.io/common/testcontext"
	"storj.io/gateway-mt/pkg/auth/badgerauth"
)

// RunSingleNode tests against a single node cluster of badgerauth.
func RunSingleNode(t *testing.T, config badgerauth.Config, fn func(ctx *testcontext.Context, t *testing.T, node *badgerauth.Node)) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	setConfigDefaults(&config)

	log := zaptest.NewLogger(t).Named("badgerauth")
	node, err := badgerauth.New(log, config)
	require.NoError(t, err)
	defer ctx.Check(node.Close)

	require.NoError(t, node.UnderlyingDB().Ping(ctx), "Ping")

	nodectx, nodecancel := context.WithCancel(ctx)
	var g errgroup.Group
	g.Go(func() error { return node.Run(nodectx) })
	defer ctx.Check(func() error {
		nodecancel()
		return g.Wait()
	})

	fn(ctx, t, node)
}

// Cluster represents a collection of badgerauth nodes.
type Cluster struct {
	Nodes []*badgerauth.Node
}

// ClusterConfig is used for configuring the cluster.
type ClusterConfig struct {
	NodeCount int
	Defaults  badgerauth.Config

	ReconfigureNode func(index int, config *badgerauth.Config)
}

// RunCluster tests against a multinode cluster of badgerauth.
func RunCluster(t *testing.T, c ClusterConfig, fn func(ctx *testcontext.Context, t *testing.T, cluster *Cluster)) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	log := zaptest.NewLogger(t).Named("badgerauth")

	var nodes []*badgerauth.Node
	for i := 0; i < c.NodeCount; i++ {
		name := strconv.Itoa(i)
		log := log.Named(name)

		config := c.Defaults
		if c.ReconfigureNode != nil {
			c.ReconfigureNode(i, &config)
		}
		config.ID = badgerauth.NodeID{byte(i)}
		setConfigDefaults(&config)

		node, err := badgerauth.New(log, config)
		require.NoError(t, err)
		defer ctx.Check(node.Close)

		require.NoError(t, node.UnderlyingDB().Ping(ctx), "Ping")

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
			err := node.Run(nodectx)
			if errs2.IsCanceled(err) {
				err = nil
			}
			return err
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
	if config.Address == "" {
		config.Address = "127.0.0.1:0"
	}
	if config.CertsDir == "" {
		config.InsecureDisableTLS = true
	}

	config.ReplicationInterval = time.Minute
	if config.ReplicationLimit == 0 {
		config.ReplicationLimit = 100
	}

	config.ConflictBackoff.Delay = 0
	config.ConflictBackoff.Max = 5 * time.Minute
	config.ConflictBackoff.Min = 100 * time.Millisecond
}
