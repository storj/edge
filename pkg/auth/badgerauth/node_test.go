// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauth_test

import (
	"testing"
	"time"

	badger "github.com/outcaste-io/badger/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"storj.io/common/rpc/rpcstatus"
	"storj.io/common/testcontext"
	"storj.io/gateway-mt/pkg/auth/authdb"
	"storj.io/gateway-mt/pkg/auth/badgerauth"
	"storj.io/gateway-mt/pkg/auth/badgerauth/badgerauthtest"
	"storj.io/gateway-mt/pkg/auth/badgerauth/pb"
)

func TestNode_Replicate_EmptyRequestResponse(t *testing.T) {
	badgerauthtest.RunSingleNode(t, badgerauth.Config{
		ID:               badgerauth.NodeID{'t', 'e', 's', 't'},
		ReplicationLimit: 123,
	}, func(ctx *testcontext.Context, t *testing.T, _ *zap.Logger, node *badgerauth.Node) {
		// empty request/response
		badgerauthtest.Replicate{
			Request: &pb.ReplicationRequest{},
			Result:  &pb.ReplicationResponse{},
		}.Check(ctx, t, node)

		badgerauthtest.Replicate{
			Request: &pb.ReplicationRequest{
				Entries: []*pb.ReplicationRequestEntry{
					{
						NodeId: []byte{'t', 'e', 's', 't'},
						Clock:  0,
					},
					{
						NodeId: []byte{'t', 's', 'e', 't'},
						Clock:  1,
					},
				},
			},
			Result: &pb.ReplicationResponse{},
		}.Check(ctx, t, node)

		badgerauthtest.Put{
			KeyHash: authdb.KeyHash{'k', 'h'},
			Record:  &authdb.Record{},
		}.Check(ctx, t, node)

		badgerauthtest.Replicate{
			Request: &pb.ReplicationRequest{
				Entries: []*pb.ReplicationRequestEntry{
					{
						NodeId: []byte{'t', 'e', 's', 't'},
						Clock:  1,
					},
					{
						NodeId: []byte{'t', 's', 'e', 't'},
						Clock:  2,
					},
				},
			},
			Result: &pb.ReplicationResponse{},
		}.Check(ctx, t, node)
	})
}

func TestNode_Replicate_OverlappingNodeIDs(t *testing.T) {
	badgerauthtest.RunSingleNode(t, badgerauth.Config{
		ID:               badgerauth.NodeID{'a', 'a'},
		ReplicationLimit: 123,
	}, func(ctx *testcontext.Context, t *testing.T, _ *zap.Logger, node *badgerauth.Node) {
		badgerauthtest.Put{
			KeyHash: authdb.KeyHash{'k', 'h'},
			Record:  &authdb.Record{},
		}.Check(ctx, t, node)

		badgerauthtest.Replicate{
			Request: &pb.ReplicationRequest{
				Entries: []*pb.ReplicationRequestEntry{
					{
						NodeId: []byte{'a'},
						Clock:  0,
					},
					{
						NodeId: []byte{'a', 'a'},
						Clock:  1,
					},
				},
			},
			Result: &pb.ReplicationResponse{},
		}.Check(ctx, t, node)
	})
}

func TestNode_Replicate_Basic(t *testing.T) {
	badgerauthtest.RunSingleNode(t, badgerauth.Config{
		ID:               badgerauth.NodeID{'a'},
		ReplicationLimit: 25,
	}, func(ctx *testcontext.Context, t *testing.T, log *zap.Logger, node *badgerauth.Node) {
		// test's outline:
		//  1. node A knows about nodes A B C D
		//  2. another node requests information about A B C D E from A
		//
		// test's plan:
		//  A: has record(s) 0-50    | request for clock > 25  | returns 25 records
		//  B: has record(s) 51      | request for clock > 0   | returns 1  records
		//  C: has record(s) 52-100  | request for clock > 12  | returns 25 records (hits the limit)
		//  D: has record(s) 100-255 | request for clock > 155 | returns 0  records
		//  E: (A doesn't know about E)
		var expectedReplicationResponseEntries []*pb.ReplicationResponseEntry

		for i := 0; i < 50; i++ {
			r := &authdb.Record{
				SatelliteAddress:     "t",
				MacaroonHead:         []byte{'e'},
				EncryptedSecretKey:   []byte{'s'},
				EncryptedAccessGrant: []byte{'t'},
				Public:               false,
			}

			kh := authdb.KeyHash{byte(i)}
			now := time.Now()

			badgerauthtest.PutAtTime{
				KeyHash: authdb.KeyHash{byte(i)},
				Record:  r,
				Time:    now,
			}.Check(ctx, t, node)

			if i >= 25 {
				expectedReplicationResponseEntries = append(expectedReplicationResponseEntries, &pb.ReplicationResponseEntry{
					NodeId:            badgerauth.NodeID{'a'}.Bytes(),
					EncryptionKeyHash: kh.Bytes(),
					Record: &pb.Record{
						CreatedAtUnix:        now.Unix(),
						Public:               false,
						SatelliteAddress:     r.SatelliteAddress,
						MacaroonHead:         r.MacaroonHead,
						EncryptedSecretKey:   r.EncryptedSecretKey,
						EncryptedAccessGrant: r.EncryptedAccessGrant,
						State:                pb.Record_CREATED,
					},
				})
			}
		}

		require.NoError(t, node.UnderlyingDB().UnderlyingDB().Update(func(txn *badger.Txn) error {
			for i := 52; i < 100; i++ {
				id := badgerauth.NodeID{'c'}
				kh := authdb.KeyHash{byte(i)}
				now := time.Now()
				record := &pb.Record{
					CreatedAtUnix:        now.Unix(),
					Public:               true,
					SatelliteAddress:     "x",
					MacaroonHead:         []byte{'y'},
					ExpiresAtUnix:        now.Add(24 * time.Hour).Unix(),
					EncryptedSecretKey:   []byte{'z'},
					EncryptedAccessGrant: []byte{'?'},
					State:                pb.Record_CREATED,
				}

				if err := badgerauth.InsertRecord(log, txn, id, kh, record); err != nil {
					return err
				}

				if i >= 52+12 && i < 52+12+25 {
					expectedReplicationResponseEntries = append(expectedReplicationResponseEntries, &pb.ReplicationResponseEntry{
						NodeId:            id.Bytes(),
						EncryptionKeyHash: kh.Bytes(),
						Record:            record,
					})
				}
			}

			for i := 100; i < 255; i++ {
				if err := badgerauth.InsertRecord(log, txn, badgerauth.NodeID{'d'}, authdb.KeyHash{byte(i)}, &pb.Record{}); err != nil {
					return err
				}
			}

			id := badgerauth.NodeID{'b'}
			kh := authdb.KeyHash{51}
			now := time.Now()
			record := &pb.Record{
				CreatedAtUnix:        now.Unix(),
				Public:               true,
				SatelliteAddress:     "a",
				MacaroonHead:         []byte{'b'},
				ExpiresAtUnix:        now.Add(24 * time.Hour).Unix(),
				EncryptedSecretKey:   []byte{'c'},
				EncryptedAccessGrant: []byte{'!'},
				State:                pb.Record_CREATED,
			}

			if err := badgerauth.InsertRecord(log, txn, id, kh, record); err != nil {
				return err
			}

			expectedReplicationResponseEntries = append(expectedReplicationResponseEntries, &pb.ReplicationResponseEntry{
				NodeId:            id.Bytes(),
				EncryptionKeyHash: kh.Bytes(),
				Record:            record,
			})

			return nil
		}))

		// The request below should produce an empty response:
		badgerauthtest.Replicate{
			Request: &pb.ReplicationRequest{
				Entries: []*pb.ReplicationRequestEntry{
					{
						NodeId: []byte{'a'},
						Clock:  50,
					},
					{
						NodeId: []byte{'b'},
						Clock:  1,
					},
					// Let's skip C.
					{
						NodeId: []byte{'d'},
						Clock:  155,
					},
				},
			},
			Result: &pb.ReplicationResponse{},
		}.Check(ctx, t, node)
		// Real request:
		badgerauthtest.Replicate{
			Request: &pb.ReplicationRequest{
				Entries: []*pb.ReplicationRequestEntry{
					{
						NodeId: []byte{'a'},
						Clock:  25,
					},
					{
						NodeId: []byte{'c'},
						Clock:  12,
					},
					{
						NodeId: []byte{'b'},
						Clock:  0,
					},
					{
						NodeId: []byte{'d'},
						Clock:  155,
					},
					{
						NodeId: []byte{'e'},
						Clock:  10000,
					},
				},
			},
			Result: &pb.ReplicationResponse{
				Entries: expectedReplicationResponseEntries,
			},
		}.Check(ctx, t, node)
	})
}

func TestNode_PeekRecord(t *testing.T) {
	badgerauthtest.RunSingleNode(t, badgerauth.Config{
		ID: badgerauth.NodeID{'p', 'e', 'e', 'k'},
	}, func(ctx *testcontext.Context, t *testing.T, _ *zap.Logger, node *badgerauth.Node) {
		records, keys, _ := badgerauthtest.CreateFullRecords(ctx, t, node, 2)

		_, err := node.Peek(ctx, &pb.PeekRequest{EncryptionKeyHash: []byte{}})
		require.Equal(t, rpcstatus.NotFound, rpcstatus.Code(err))

		_, err = node.Peek(ctx, &pb.PeekRequest{EncryptionKeyHash: []byte{'a'}})
		require.Equal(t, rpcstatus.NotFound, rpcstatus.Code(err))

		_, err = node.Peek(ctx, &pb.PeekRequest{EncryptionKeyHash: make([]byte, 33)})
		require.Equal(t, rpcstatus.InvalidArgument, rpcstatus.Code(err))

		resp, err := node.Peek(ctx, &pb.PeekRequest{EncryptionKeyHash: keys[0].Bytes()})
		require.NoError(t, err)
		require.Equal(t, records[keys[0]].EncryptedAccessGrant, resp.Record.EncryptedAccessGrant)

		resp, err = node.Peek(ctx, &pb.PeekRequest{EncryptionKeyHash: keys[1].Bytes()})
		require.NoError(t, err)
		require.Equal(t, records[keys[1]].EncryptedAccessGrant, resp.Record.EncryptedAccessGrant)
	})
}

func TestPeer_PeekRecord(t *testing.T) {
	badgerauthtest.RunCluster(t, badgerauthtest.ClusterConfig{
		NodeCount: 2,
	}, func(ctx *testcontext.Context, t *testing.T, cluster *badgerauthtest.Cluster) {
		records, keys, _ := badgerauthtest.CreateFullRecords(ctx, t, cluster.Nodes[0], 2)

		peer := badgerauth.NewPeer(cluster.Nodes[0], cluster.Nodes[0].Address())
		record, err := peer.Peek(ctx, keys[0])
		require.NoError(t, err)
		require.Equal(t, records[keys[0]].EncryptedAccessGrant, record.EncryptedAccessGrant)

		_, err = peer.Peek(ctx, authdb.KeyHash{'a'})
		require.Equal(t, rpcstatus.NotFound, rpcstatus.Code(err))
	})
}

func TestPeer_DialFailureIsReported(t *testing.T) {
	badgerauthtest.RunCluster(t, badgerauthtest.ClusterConfig{
		NodeCount: 2,
	}, func(ctx *testcontext.Context, t *testing.T, cluster *badgerauthtest.Cluster) {
		_, keys, _ := badgerauthtest.CreateFullRecords(ctx, t, cluster.Nodes[0], 2)

		_, err := badgerauth.NewPeer(cluster.Nodes[0], "").Peek(ctx, keys[0])
		require.Error(t, err)

		assert.True(t, badgerauth.DialError.Has(err))
		assert.Nil(t, badgerauth.IgnoreDialFailures(err))
	})
}

func TestNew_BadNodeID(t *testing.T) {
	t.Parallel()

	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	log := zaptest.NewLogger(t)
	defer ctx.Check(log.Sync)
	cfg := badgerauth.Config{
		ID:         badgerauth.NodeID{'a'},
		FirstStart: true,
		Path:       ctx.File("badger.db"),
		CertsDir:   ctx.Dir("certs-dir"),
	}

	n, err := badgerauth.New(log, cfg)
	require.NoError(t, err)
	require.NoError(t, n.Close())

	cfg.ID = badgerauth.NodeID{'b'}
	n, err = badgerauth.New(log, cfg)
	require.Nil(t, n)
	require.Error(t, err)
	require.True(t, badgerauth.ErrDBStartedWithDifferentNodeID.Has(err))
}

func TestNew_CheckFirstStart(t *testing.T) {
	t.Parallel()

	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	log := zaptest.NewLogger(t)
	defer ctx.Check(log.Sync)
	cfg := badgerauth.Config{
		FirstStart: false,
	}

	n, err := badgerauth.New(log, cfg)
	require.Nil(t, n)
	require.Error(t, err)
}
