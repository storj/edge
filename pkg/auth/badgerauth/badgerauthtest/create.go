// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauthtest

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"storj.io/common/testcontext"
	"storj.io/common/testrand"
	"storj.io/gateway-mt/pkg/auth/authdb"
	"storj.io/gateway-mt/pkg/auth/badgerauth"
	"storj.io/gateway-mt/pkg/auth/badgerauth/pb"
)

// CreateFullRecords creates count of records with random data at node returning
// created records and corresponding replication log entries.
func CreateFullRecords(
	ctx *testcontext.Context,
	t testing.TB,
	node *badgerauth.Node,
	count int,
) (
	records map[authdb.KeyHash]*authdb.Record,
	keys []authdb.KeyHash,
	entries []ReplicationLogEntryWithTTL,
) {
	records = make(map[authdb.KeyHash]*authdb.Record)

	for i := 0; i < count; i++ {
		marker := testrand.RandAlphaNumeric(32)

		var keyHash authdb.KeyHash
		require.NoError(t, keyHash.SetBytes(marker))

		// TODO(artur): make expiresAt configurable or random per record.
		expiresAt := time.Unix(time.Now().Add(time.Hour).Unix(), 0)

		record := &authdb.Record{
			SatelliteAddress:     string(marker),
			MacaroonHead:         marker,
			EncryptedSecretKey:   marker,
			EncryptedAccessGrant: marker,
			ExpiresAt:            &expiresAt,
			Public:               testrand.Intn(1) == 0,
		}

		keys = append(keys, keyHash)
		records[keyHash] = record
		entries = append(entries, ReplicationLogEntryWithTTL{
			Entry: badgerauth.ReplicationLogEntry{
				ID:      node.ID(),
				Clock:   badgerauth.Clock(i + 1),
				KeyHash: keyHash,
				State:   pb.Record_CREATED,
			},
			ExpiresAt: expiresAt,
		})

		Put{
			KeyHash: keyHash,
			Record:  record,
			Error:   nil,
		}.Check(ctx, t, node)
	}

	return records, keys, entries
}
