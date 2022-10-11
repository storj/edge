// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauth_test

import (
	"crypto/tls"
	"math/rand"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"storj.io/common/testcontext"
	"storj.io/common/testrand"
	"storj.io/drpc/drpcconn"
	"storj.io/gateway-mt/pkg/auth/authdb"
	"storj.io/gateway-mt/pkg/auth/badgerauth"
	"storj.io/gateway-mt/pkg/auth/badgerauth/badgerauthtest"
	"storj.io/gateway-mt/pkg/auth/badgerauth/pb"
)

func TestServer(t *testing.T) {
	badgerauthtest.RunSingleNode(t, badgerauth.Config{}, func(ctx *testcontext.Context, t *testing.T, _ *zap.Logger, node *badgerauth.Node) {
		rawconn, err := (&net.Dialer{}).DialContext(ctx, "tcp", node.Address())
		require.NoError(t, err)
		conn := drpcconn.New(rawconn)
		defer ctx.Check(conn.Close)

		client := pb.NewDRPCReplicationServiceClient(conn)
		resp, err := client.Ping(ctx, &pb.PingRequest{})
		require.NoError(t, err)
		require.Equal(t, node.ID().Bytes(), resp.NodeId)
	})
}

func TestServerCerts(t *testing.T) {
	certsctx := testcontext.New(t)
	trusted := createTestingPool(t, 2)

	err := os.WriteFile(certsctx.File("alpha", "ca.crt"), encodeCertificate(trusted.CA.Raw), 0644)
	require.NoError(t, err)
	err = os.WriteFile(certsctx.File("alpha", "node.crt"), encodeCertificate(trusted.Certs[0].Certificate[0]), 0644)
	require.NoError(t, err)
	err = os.WriteFile(certsctx.File("alpha", "node.key"), encodePrivateKey(trusted.Certs[0].PrivateKey), 0644)
	require.NoError(t, err)

	err = os.WriteFile(certsctx.File("beta", "ca.crt"), encodeCertificate(trusted.CA.Raw), 0644)
	require.NoError(t, err)
	err = os.WriteFile(certsctx.File("beta", "node.crt"), encodeCertificate(trusted.Certs[1].Certificate[0]), 0644)
	require.NoError(t, err)
	err = os.WriteFile(certsctx.File("beta", "node.key"), encodePrivateKey(trusted.Certs[1].PrivateKey), 0644)
	require.NoError(t, err)

	badgerauthtest.RunSingleNode(t, badgerauth.Config{
		CertsDir: certsctx.Dir("alpha"),
	}, func(ctx *testcontext.Context, t *testing.T, _ *zap.Logger, node *badgerauth.Node) {
		config, err := badgerauth.TLSOptions{CertsDir: certsctx.Dir("beta")}.Load()
		require.NoError(t, err)

		dialer := tls.Dialer{Config: config}
		rawconn, err := dialer.DialContext(ctx, "tcp", node.Address())
		require.NoError(t, err)
		conn := drpcconn.New(rawconn)
		defer ctx.Check(conn.Close)

		client := pb.NewDRPCReplicationServiceClient(conn)
		resp, err := client.Ping(ctx, &pb.PingRequest{})
		require.NoError(t, err)
		require.Equal(t, node.ID().Bytes(), resp.NodeId)
	})
}

func TestCluster(t *testing.T) {
	badgerauthtest.RunCluster(t, badgerauthtest.ClusterConfig{
		NodeCount: 3,
	}, func(ctx *testcontext.Context, t *testing.T, cluster *badgerauthtest.Cluster) {
		testPing(ctx, t, cluster)
	})
}

func TestCluster_Certs(t *testing.T) {
	certsctx := testcontext.New(t)
	trusted := createTestingPool(t, 3)

	for i, cert := range trusted.Certs {
		err := os.WriteFile(certsctx.File(strconv.Itoa(i), "ca.crt"), encodeCertificate(trusted.CA.Raw), 0644)
		require.NoError(t, err)
		err = os.WriteFile(certsctx.File(strconv.Itoa(i), "node.crt"), encodeCertificate(cert.Certificate[0]), 0644)
		require.NoError(t, err)
		err = os.WriteFile(certsctx.File(strconv.Itoa(i), "node.key"), encodePrivateKey(cert.PrivateKey), 0644)
		require.NoError(t, err)
	}

	badgerauthtest.RunCluster(t, badgerauthtest.ClusterConfig{
		NodeCount: 3,
		ReconfigureNode: func(index int, config *badgerauth.Config) {
			config.CertsDir = certsctx.Dir(strconv.Itoa(index))
		},
	}, func(ctx *testcontext.Context, t *testing.T, cluster *badgerauthtest.Cluster) {
		testPing(ctx, t, cluster)
	})
}

func testPing(ctx *testcontext.Context, t *testing.T, cluster *badgerauthtest.Cluster) {
	cluster.Nodes[0].SyncCycle.TriggerWait()
	peers := cluster.Nodes[0].TestingPeers(ctx)
	require.Len(t, peers, 2)
	for _, peer := range peers {
		status := peer.Status()
		require.Equal(t, true, status.LastWasUp)
		require.Nil(t, status.LastError)
	}
}

func TestCluster_Replication(t *testing.T) {
	const limit = 100

	badgerauthtest.RunCluster(t, badgerauthtest.ClusterConfig{
		NodeCount: 3,
		Defaults: badgerauth.Config{
			ReplicationLimit: limit,
		},
	}, func(ctx *testcontext.Context, t *testing.T, cluster *badgerauthtest.Cluster) {
		testReplication(ctx, t, cluster, 2, limit)
	})
}

func TestCluster_ReplicationSingleLoop(t *testing.T) {
	const limit = 100

	badgerauthtest.RunCluster(t, badgerauthtest.ClusterConfig{
		NodeCount: 3,
		Defaults: badgerauth.Config{
			ReplicationLimit: limit,
		},
	}, func(ctx *testcontext.Context, t *testing.T, cluster *badgerauthtest.Cluster) {
		testReplicationSingleLoop(ctx, t, cluster, 2, limit)
	})
}

func TestCluster_ReplicationManyRecords(t *testing.T) {
	count := 1234
	if testing.Short() {
		count = 123
	}

	const limit = 100

	badgerauthtest.RunCluster(t, badgerauthtest.ClusterConfig{
		NodeCount: 5,
		Defaults: badgerauth.Config{
			ReplicationLimit: limit,
		},
	}, func(ctx *testcontext.Context, t *testing.T, cluster *badgerauthtest.Cluster) {
		testReplication(ctx, t, cluster, count, limit)
	})
}

func TestCluster_ReplicationManyRecordsSingleLoop(t *testing.T) {
	count := 1234
	if testing.Short() {
		count = 123
	}

	const limit = 100

	badgerauthtest.RunCluster(t, badgerauthtest.ClusterConfig{
		NodeCount: 5,
		Defaults: badgerauth.Config{
			ReplicationLimit: limit,
		},
	}, func(ctx *testcontext.Context, t *testing.T, cluster *badgerauthtest.Cluster) {
		testReplicationSingleLoop(ctx, t, cluster, count, limit)
	})
}

func testReplication(ctx *testcontext.Context, t *testing.T, cluster *badgerauthtest.Cluster, count, limit int) {
	expectedRecords := make(map[authdb.KeyHash]*authdb.Record)
	var expectedEntries []badgerauthtest.ReplicationLogEntryWithTTL

	for _, n := range cluster.Nodes {
		records, _, entries := badgerauthtest.CreateFullRecords(ctx, t, n, count)
		appendRecords(expectedRecords, records)
		expectedEntries = append(expectedEntries, entries...)
	}

	for i := 0; i < count/limit+1; i++ {
		for _, n := range cluster.Nodes {
			n.SyncCycle.TriggerWait()
		}
	}

	ensureClusterConvergence(ctx, t, cluster, expectedRecords, expectedEntries)
}

func testReplicationSingleLoop(ctx *testcontext.Context, t *testing.T, cluster *badgerauthtest.Cluster, count, limit int) {
	expectedRecords := make(map[authdb.KeyHash]*authdb.Record)
	var expectedEntries []badgerauthtest.ReplicationLogEntryWithTTL

	for _, n := range cluster.Nodes {
		records, _, entries := badgerauthtest.CreateFullRecords(ctx, t, n, count)
		appendRecords(expectedRecords, records)
		expectedEntries = append(expectedEntries, entries...)

		for i := 0; i < count/limit+1; i++ {
			for _, n := range cluster.Nodes {
				n.SyncCycle.TriggerWait()
			}
		}

		ensureClusterConvergence(ctx, t, cluster, expectedRecords, expectedEntries)
	}
}

func TestCluster_ReplicationRandomized(t *testing.T) {
	maxCount := 100
	if testing.Short() {
		maxCount = 10
	}

	badgerauthtest.RunCluster(t, badgerauthtest.ClusterConfig{
		NodeCount: testrand.Intn(7),
		ReconfigureNode: func(index int, config *badgerauth.Config) {
			config.ReplicationLimit = testrand.Intn(index+1) + 1
		},
	}, func(ctx *testcontext.Context, t *testing.T, cluster *badgerauthtest.Cluster) {
		expectedRecords := make(map[authdb.KeyHash]*authdb.Record)
		var expectedEntries []badgerauthtest.ReplicationLogEntryWithTTL

		var max int
		for _, n := range cluster.Nodes {
			count := testrand.Intn(maxCount + 1)

			if count > max {
				max = count
			}

			records, _, entries := badgerauthtest.CreateFullRecords(ctx, t, n, count)
			appendRecords(expectedRecords, records)
			expectedEntries = append(expectedEntries, entries...)
		}

		for i := 0; i < max; i++ {
			for _, n := range shuffleNodesOrder(cluster.Nodes) {
				n.SyncCycle.TriggerWait()
			}
		}

		ensureClusterConvergence(ctx, t, cluster, expectedRecords, expectedEntries)
	})
}

func TestCluster_ReplicationRandomizedSingleLoop(t *testing.T) {
	badgerauthtest.RunCluster(t, badgerauthtest.ClusterConfig{
		NodeCount: testrand.Intn(7),
		ReconfigureNode: func(index int, config *badgerauth.Config) {
			config.ReplicationLimit = testrand.Intn(index+1) + 1
		},
	}, func(ctx *testcontext.Context, t *testing.T, cluster *badgerauthtest.Cluster) {
		expectedRecords := make(map[authdb.KeyHash]*authdb.Record)
		var expectedEntries []badgerauthtest.ReplicationLogEntryWithTTL

		for _, n := range shuffleNodesOrder(cluster.Nodes) {
			count := testrand.Intn(7)

			records, _, entries := badgerauthtest.CreateFullRecords(ctx, t, n, count)
			appendRecords(expectedRecords, records)
			expectedEntries = append(expectedEntries, entries...)

			for i := 0; i < count; i++ {
				for _, n := range shuffleNodesOrder(cluster.Nodes) {
					n.SyncCycle.TriggerWait()
				}
			}

			ensureClusterConvergence(ctx, t, cluster, expectedRecords, expectedEntries)
		}
	})
}

func appendRecords(dst, src map[authdb.KeyHash]*authdb.Record) {
	for k, r := range src {
		dst[k] = r
	}
}

func shuffleNodesOrder(nodes []*badgerauth.Node) []*badgerauth.Node {
	shuffled := make([]*badgerauth.Node, len(nodes))

	copy(shuffled, nodes)

	rand.New(rand.NewSource(time.Now().UnixNano())).Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})

	return shuffled
}

func ensureClusterConvergence(
	ctx *testcontext.Context,
	t *testing.T,
	cluster *badgerauthtest.Cluster,
	records map[authdb.KeyHash]*authdb.Record,
	entries []badgerauthtest.ReplicationLogEntryWithTTL,
) {
	for _, n := range cluster.Nodes {
		for k, r := range records {
			badgerauthtest.Get{
				KeyHash: k,
				Result:  r,
				Error:   nil,
			}.Check(ctx, t, n)
		}
		badgerauthtest.VerifyReplicationLog{
			Entries: entries,
		}.Check(ctx, t, n)
	}
}

// TestBroadcastedGet tests whether nodes can reach out to other nodes for
// records they don't have before replication happens.
func TestBroadcastedGet(t *testing.T) {
	badgerauthtest.RunCluster(t, badgerauthtest.ClusterConfig{
		NodeCount: 3,
	}, func(ctx *testcontext.Context, t *testing.T, cluster *badgerauthtest.Cluster) {
		for _, n := range cluster.Nodes {
			n.SyncCycle.Pause() // ensure records won't replicate during the test
		}

		records, keys, _ := badgerauthtest.CreateFullRecords(ctx, t, cluster.Nodes[0], 2)

		for _, n := range cluster.Nodes {
			for _, k := range keys {
				r, err := n.Get(ctx, k)
				require.NoError(t, err)
				require.NotNil(t, r)
				assert.Equal(t, records[k].SatelliteAddress, r.SatelliteAddress)
				assert.Equal(t, records[k].MacaroonHead, r.MacaroonHead)
				assert.Equal(t, records[k].EncryptedSecretKey, r.EncryptedSecretKey)
				assert.Equal(t, records[k].EncryptedAccessGrant, r.EncryptedAccessGrant)
				assert.Equal(t, records[k].ExpiresAt, r.ExpiresAt)
				assert.Equal(t, records[k].Public, r.Public)
			}
			r, err := n.Get(ctx, authdb.KeyHash{'a'}) // "a" is a nonexistent record
			require.NoError(t, err)
			require.Nil(t, r)
		}
	})
}
