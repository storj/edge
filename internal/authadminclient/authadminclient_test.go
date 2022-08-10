// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package authadminclient_test

import (
	"encoding/hex"
	"io"
	"log"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"storj.io/common/encryption"
	"storj.io/common/grant"
	"storj.io/common/storj"
	"storj.io/common/testcontext"
	client "storj.io/gateway-mt/internal/authadminclient"
	"storj.io/gateway-mt/pkg/auth/authdb"
	"storj.io/gateway-mt/pkg/auth/badgerauth"
	"storj.io/gateway-mt/pkg/auth/badgerauth/badgerauthtest"
)

const (
	testSatelliteURL = "1SYXsAycDPUu4z2ZksJD5fh5nTDcH3vCFHnpcVye5XuL1NrYV@s"
	testAPIKey       = "13Yqe3oHi5dcnGhMu2ru3cmePC9iEYv6nDrYMbLRh4wre1KtVA9SFwLNAuuvWwc43b9swRsrfsnrbuTHQ6TJKVt4LjGnaARN9PhxJEu"
	testAccessGrant  = "13J4Upun87ATb3T5T5sDXVeQaCzWFZeF9Ly4ELfxS5hUwTL8APEkwahTEJ1wxZjyErimiDs3kgid33kDLuYPYtwaY7Toy32mCTapfrUB814X13RiA844HPWK3QLKZb9cAoVceTowmNZXWbcUMKNbkMHCURE4hn8ZrdHPE3S86yngjvDxwKmarfGx"
)

func TestGetRecord(t *testing.T) {
	badgerauthtest.RunCluster(t, badgerauthtest.ClusterConfig{
		NodeCount: 3,
	}, func(ctx *testcontext.Context, t *testing.T, cluster *badgerauthtest.Cluster) {
		noAddrClient := client.New(client.Config{}, log.New(io.Discard, "", 0))
		client := client.New(client.Config{
			NodeAddresses:      cluster.Addresses(),
			InsecureDisableTLS: true,
		}, log.New(io.Discard, "", 0))

		_, keys, _ := badgerauthtest.CreateFullRecords(ctx, t, cluster.Nodes[0], 1)
		for _, node := range cluster.Nodes {
			node.SyncCycle.TriggerWait()
		}

		record, err := client.Get(ctx, keys[0].ToHex())
		require.NoError(t, err)
		require.Equal(t, "", record.DecryptedAccessGrant)

		encKey, err := authdb.NewEncryptionKey()
		require.NoError(t, err)
		sk := encKey.ToStorjKey()
		encAccessGrant, err := encryption.Encrypt([]byte(testAccessGrant), storj.EncAESGCM, &sk, &storj.Nonce{1})
		require.NoError(t, err)
		require.NotEqual(t, testAccessGrant, encAccessGrant)

		parsed, err := grant.ParseAccess(testAccessGrant)
		require.NoError(t, err)

		expiresAt := time.Unix(time.Now().Unix(), 0).Add(time.Hour)
		badgerauthtest.Put{
			KeyHash: encKey.Hash(),
			Record: &authdb.Record{
				Public:               true,
				SatelliteAddress:     testSatelliteURL,
				MacaroonHead:         parsed.APIKey.Head(),
				EncryptedAccessGrant: encAccessGrant,
				ExpiresAt:            &expiresAt,
			},
		}.Check(ctx, t, cluster.Nodes[0])
		for _, node := range cluster.Nodes {
			node.SyncCycle.TriggerWait()
		}

		_, err = noAddrClient.Get(ctx, encKey.ToBase32())
		require.Error(t, err)

		record, err = client.Get(ctx, encKey.ToBase32())
		require.NoError(t, err)
		require.True(t, record.Public)
		require.Equal(t, testSatelliteURL, record.SatelliteAddress)
		require.Equal(t, encAccessGrant, record.EncryptedAccessGrant)
		require.Equal(t, testAccessGrant, record.DecryptedAccessGrant)
		require.Equal(t, testAPIKey, record.APIKey)
		require.Equal(t, parsed.APIKey.Head(), record.MacaroonHead)
		require.Equal(t, hex.EncodeToString(parsed.APIKey.Head()), record.MacaroonHeadHex)
		require.Equal(t, expiresAt.Unix(), record.ExpiresAtUnix)
	})
}

func TestInvalidateRecord(t *testing.T) {
	badgerauthtest.RunCluster(t, badgerauthtest.ClusterConfig{
		NodeCount: 3,
	}, func(ctx *testcontext.Context, t *testing.T, cluster *badgerauthtest.Cluster) {
		noAddrClient := client.New(client.Config{}, log.New(io.Discard, "", 0))
		client := client.New(client.Config{
			NodeAddresses:      cluster.Addresses(),
			InsecureDisableTLS: true,
		}, log.New(io.Discard, "", 0))

		records, keys, entries := badgerauthtest.CreateFullRecords(ctx, t, cluster.Nodes[0], 5)
		for _, node := range cluster.Nodes {
			node.SyncCycle.TriggerWait()
		}

		require.Error(t, noAddrClient.Invalidate(ctx, keys[0].ToHex(), ""))
		require.NoError(t, client.Invalidate(ctx, keys[0].ToHex(), "no more access"))

		for _, node := range cluster.Nodes {
			badgerauthtest.Get{
				KeyHash: keys[0],
				Error:   badgerauth.Error.Wrap(authdb.Invalid.New("no more access")),
			}.Check(ctx, t, node)
		}

		delete(records, keys[0])
		verifyClusterRecords(ctx, t, cluster, records, entries)
	})
}

func TestUnpublishRecord(t *testing.T) {
	badgerauthtest.RunCluster(t, badgerauthtest.ClusterConfig{
		NodeCount: 3,
	}, func(ctx *testcontext.Context, t *testing.T, cluster *badgerauthtest.Cluster) {
		noAddrClient := client.New(client.Config{}, log.New(io.Discard, "", 0))
		client := client.New(client.Config{
			NodeAddresses:      cluster.Addresses(),
			InsecureDisableTLS: true,
		}, log.New(io.Discard, "", 0))

		records, keys, entries := badgerauthtest.CreateFullRecords(ctx, t, cluster.Nodes[0], 5)
		for _, node := range cluster.Nodes {
			node.SyncCycle.TriggerWait()
		}

		require.True(t, records[keys[0]].Public)

		require.Error(t, noAddrClient.Unpublish(ctx, keys[0].ToHex()))
		require.NoError(t, client.Unpublish(ctx, keys[0].ToHex()))

		records[keys[0]].Public = false
		verifyClusterRecords(ctx, t, cluster, records, entries)
	})
}

func TestDeleteRecord(t *testing.T) {
	badgerauthtest.RunCluster(t, badgerauthtest.ClusterConfig{
		NodeCount: 3,
	}, func(ctx *testcontext.Context, t *testing.T, cluster *badgerauthtest.Cluster) {
		noAddrClient := client.New(client.Config{}, log.New(io.Discard, "", 0))
		client := client.New(client.Config{
			NodeAddresses:      cluster.Addresses(),
			InsecureDisableTLS: true,
		}, log.New(io.Discard, "", 0))

		records, keys, entries := badgerauthtest.CreateFullRecords(ctx, t, cluster.Nodes[0], 5)
		for _, node := range cluster.Nodes {
			node.SyncCycle.TriggerWait()
		}

		require.Error(t, noAddrClient.Delete(ctx, keys[0].ToHex()))
		require.NoError(t, client.Delete(ctx, keys[0].ToHex()))

		delete(records, keys[0])
		verifyClusterRecords(ctx, t, cluster, records, entries[1:])
	})
}

func verifyClusterRecords(
	ctx *testcontext.Context,
	t *testing.T,
	cluster *badgerauthtest.Cluster,
	records map[authdb.KeyHash]*authdb.Record,
	entries []badgerauthtest.ReplicationLogEntryWithTTL,
) {
	for _, node := range cluster.Nodes {
		for key, record := range records {
			badgerauthtest.Get{
				KeyHash: key,
				Result:  record,
			}.Check(ctx, t, node)
		}
		badgerauthtest.VerifyReplicationLog{
			Entries: entries,
		}.Check(ctx, t, node)
	}
}
