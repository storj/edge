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
)

// TODO(artur): it might not be worth differentiating between asserts and
// requires. Maybe we should just change everything to requires here.

// Put is for testing badgerauth.(*Node).Put method.
type Put struct {
	KeyHash authdb.KeyHash
	Record  *authdb.Record
	Error   error
}

// Check runs the test.
func (step Put) Check(ctx *testcontext.Context, t testing.TB, node *badgerauth.Node) {
	err := node.Put(ctx, step.KeyHash, step.Record)
	if step.Error != nil {
		require.EqualError(t, step.Error, err.Error())
	} else {
		require.NoError(t, err)
	}
}

// PutAtTime is for testing badgerauth.(*Node).PutAtTime method.
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
		require.EqualError(t, step.Error, err.Error())
	} else {
		require.NoError(t, err)
	}
}

// Get is for testing badgerauth.(*Node).Get method.
type Get struct {
	KeyHash authdb.KeyHash
	Result  *authdb.Record
	Error   error
}

// Check runs the test.
func (step Get) Check(ctx *testcontext.Context, t testing.TB, node *badgerauth.Node) {
	got, err := node.Get(ctx, step.KeyHash)
	if step.Error != nil {
		require.EqualError(t, step.Error, err.Error())
	} else {
		require.NoError(t, err)
	}
	assert.Equal(t, step.Result, got)
}

// GetAtTime is for testing badgerauth.(*Node).GetAtTime method.
type GetAtTime struct {
	KeyHash authdb.KeyHash
	Result  *authdb.Record
	Error   error
	Time    time.Time
}

// Check runs the test.
func (step GetAtTime) Check(ctx *testcontext.Context, t testing.TB, node *badgerauth.Node) {
	got, err := node.GetAtTime(ctx, step.KeyHash, step.Time)
	if step.Error != nil {
		require.EqualError(t, step.Error, err.Error())
	} else {
		require.NoError(t, err)
	}
	assert.Equal(t, step.Result, got)
}

// Delete is for testing badgerauth.(*Node).Delete method.
type Delete struct {
	KeyHash authdb.KeyHash
	Error   error
}

// Check runs the test.
func (step Delete) Check(ctx *testcontext.Context, t testing.TB, node *badgerauth.Node) {
	err := node.Delete(ctx, step.KeyHash)
	if step.Error != nil {
		require.EqualError(t, step.Error, err.Error())
	} else {
		require.NoError(t, err)
	}
}

// DeleteAtTime is for testing badgerauth.(*Node).DeleteAtTime method.
type DeleteAtTime struct {
	KeyHash authdb.KeyHash
	Error   error
	Time    time.Time
}

// Check runs the test.
func (step DeleteAtTime) Check(ctx *testcontext.Context, t testing.TB, node *badgerauth.Node) {
	err := node.DeleteAtTime(ctx, step.KeyHash, step.Time)
	if step.Error != nil {
		require.EqualError(t, step.Error, err.Error())
	} else {
		require.NoError(t, err)
	}
}

// Invalidate is for testing badgerauth.(*Node).Invalidate method.
type Invalidate struct {
	KeyHash authdb.KeyHash
	Reason  string
	Error   error
}

// Check runs the test.
func (step Invalidate) Check(ctx *testcontext.Context, t testing.TB, node *badgerauth.Node) {
	err := node.Invalidate(ctx, step.KeyHash, step.Reason)
	if step.Error != nil {
		require.EqualError(t, step.Error, err.Error())
	} else {
		require.NoError(t, err)
	}
}

// InvalidateAtTime is for testing badgerauth.(*Node).InvalidateAtTime method.
type InvalidateAtTime struct {
	KeyHash authdb.KeyHash
	Reason  string
	Error   error
	Time    time.Time
}

// Check runs the test.
func (step InvalidateAtTime) Check(ctx *testcontext.Context, t testing.TB, node *badgerauth.Node) {
	err := node.InvalidateAtTime(ctx, step.KeyHash, step.Reason, step.Time)
	if step.Error != nil {
		require.EqualError(t, step.Error, err.Error())
	} else {
		require.NoError(t, err)
	}
}

// VerifyReplicationLog is for verifying the state of the replication log.
type VerifyReplicationLog struct {
	Entries [][]byte
}

// Check runs the test.
func (step VerifyReplicationLog) Check(ctx *testcontext.Context, t testing.TB, db *badger.DB) {
	var actual [][]byte

	err := db.View(func(txn *badger.Txn) error {
		opt := badger.DefaultIteratorOptions
		opt.PrefetchValues = false
		opt.Prefix = []byte("replication_log/")
		it := txn.NewIterator(opt)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			actual = append(actual, it.Item().KeyCopy(nil))
		}
		return nil
	})
	require.NoError(t, err)

	// copy step.Entries so we don't sort the original slice
	expected := make([][]byte, len(step.Entries))
	copy(expected, step.Entries)
	sort.Slice(expected, func(i, j int) bool {
		return bytes.Compare(expected[i], expected[j]) == -1
	})

	assert.Equal(t, expected, actual)
}

// Clock is for verifying the db state of the clock.
type Clock struct {
	NodeID badgerauth.NodeID
	Value  int
}

// Check runs the test.
func (step Clock) Check(t testing.TB, db *badger.DB) {
	require.NoError(t, db.View(func(txn *badger.Txn) error {
		current, err := badgerauth.ReadClock(txn, step.NodeID)
		if err != nil {
			return err
		}
		assert.EqualValues(t, step.Value, current)
		return nil
	}))
}
