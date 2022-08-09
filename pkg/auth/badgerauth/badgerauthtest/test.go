// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauthtest

import (
	"bytes"
	"sort"
	"testing"
	"time"

	badger "github.com/outcaste-io/badger/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"storj.io/common/testcontext"
	"storj.io/gateway-mt/pkg/auth/authdb"
	"storj.io/gateway-mt/pkg/auth/badgerauth"
	"storj.io/gateway-mt/pkg/auth/badgerauth/pb"
)

// TODO(artur): it might not be worth differentiating between asserts and
// requires. Maybe we should just change everything to requires here.

// Put is for testing badgerauth.(*DB).Put method.
type Put struct {
	KeyHash authdb.KeyHash
	Record  *authdb.Record
	Error   error
}

// Check runs the test.
func (step Put) Check(ctx *testcontext.Context, t testing.TB, node *badgerauth.Node) {
	err := node.Put(ctx, step.KeyHash, step.Record)
	if step.Error != nil {
		require.Error(t, err)
		require.EqualError(t, step.Error, err.Error())
	} else {
		require.NoError(t, err)
	}
}

// PutAtTime is for testing badgerauth.(*DB).PutAtTime method.
type PutAtTime struct {
	KeyHash authdb.KeyHash
	Record  *authdb.Record
	Error   error
	Time    time.Time
}

// Check runs the test.
func (step PutAtTime) Check(ctx *testcontext.Context, t testing.TB, node *badgerauth.Node) {
	err := node.PutAtTime(ctx, step.KeyHash, step.Record, step.Time)
	if step.Error != nil {
		require.Error(t, err)
		require.EqualError(t, step.Error, err.Error())
	} else {
		require.NoError(t, err)
	}
}

// Get is for testing badgerauth.(*DB).Get method.
type Get struct {
	KeyHash authdb.KeyHash
	Result  *authdb.Record
	Error   error
}

// Check runs the test.
func (step Get) Check(ctx *testcontext.Context, t testing.TB, node *badgerauth.Node) {
	got, err := node.Get(ctx, step.KeyHash)
	if step.Error != nil {
		require.Error(t, err)
		require.EqualError(t, step.Error, err.Error())
	} else {
		require.NoError(t, err)
	}
	assert.Equal(t, step.Result, got)
}

// ReplicationLogEntryWithTTL wraps ReplicationLogEntry with an expiration time,
// so it's convenient while verifying the state of the replication log.
type ReplicationLogEntryWithTTL struct {
	Entry     badgerauth.ReplicationLogEntry
	ExpiresAt time.Time
}

// VerifyReplicationLog is for verifying the state of the replication log.
type VerifyReplicationLog struct {
	Entries []ReplicationLogEntryWithTTL
}

// Check runs the test.
func (step VerifyReplicationLog) Check(ctx *testcontext.Context, t testing.TB, node *badgerauth.Node) {
	var actual []ReplicationLogEntryWithTTL

	err := node.UnderlyingDB().UnderlyingDB().View(func(txn *badger.Txn) error {
		opt := badger.DefaultIteratorOptions
		opt.PrefetchValues = false
		opt.Prefix = []byte("replication_log/")
		it := txn.NewIterator(opt)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			var entry ReplicationLogEntryWithTTL
			if err := entry.Entry.SetBytes(it.Item().Key()); err != nil {
				return err
			}
			if it.Item().ExpiresAt() > 0 {
				entry.ExpiresAt = time.Unix(int64(it.Item().ExpiresAt()), 0)
			}
			actual = append(actual, entry)
		}
		return nil
	})
	require.NoError(t, err)

	// copy step.Entries so we don't sort the original slice
	expected := make([]ReplicationLogEntryWithTTL, len(step.Entries))
	copy(expected, step.Entries)
	sort.Slice(expected, func(i, j int) bool {
		return bytes.Compare(expected[i].Entry.Bytes(), expected[j].Entry.Bytes()) == -1
	})

	require.Len(t, actual, len(expected))

	for i, e := range expected {
		assert.Equal(t, e.Entry, actual[i].Entry, i)
		assert.WithinDuration(t, e.ExpiresAt, actual[i].ExpiresAt, time.Second, i)
	}
}

// Clock is for verifying the db state of the clock.
type Clock struct {
	NodeID badgerauth.NodeID
	Value  int
}

// Check runs the test.
func (step Clock) Check(t testing.TB, node *badgerauth.Node) {
	require.NoError(t, node.UnderlyingDB().UnderlyingDB().View(func(txn *badger.Txn) error {
		current, err := badgerauth.ReadClock(txn, step.NodeID)
		if err != nil {
			return err
		}
		assert.EqualValues(t, step.Value, current)
		return nil
	}))
}

// Replicate is for testing the badgerauth.(*Node).Replicate method.
type Replicate struct {
	Request *pb.ReplicationRequest
	Result  *pb.ReplicationResponse
	Error   error
}

// Check runs the test.
func (step Replicate) Check(ctx *testcontext.Context, t testing.TB, node *badgerauth.Node) {
	got, err := node.Replicate(ctx, step.Request)
	if step.Error != nil {
		require.Error(t, err)
		require.EqualError(t, step.Error, err.Error())
	} else {
		require.NoError(t, err)
	}
	assert.True(t, pb.Equal(got, step.Result))
}
