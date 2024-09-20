// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauthtest

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"storj.io/common/testcontext"
	"storj.io/edge/pkg/auth/authdb"
	"storj.io/edge/pkg/auth/badgerauth"
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
func (step Put) Check(ctx *testcontext.Context, t testing.TB, db *badgerauth.DB) {
	err := db.Put(ctx, step.KeyHash, step.Record)
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
func (step PutAtTime) Check(ctx *testcontext.Context, t testing.TB, db *badgerauth.DB) {
	err := db.PutAtTime(ctx, step.KeyHash, step.Record, step.Time)
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
func (step Get) Check(ctx *testcontext.Context, t testing.TB, db *badgerauth.DB) {
	got, err := db.Get(ctx, step.KeyHash)
	if step.Error != nil {
		require.Error(t, err)
		require.EqualError(t, step.Error, err.Error())
	} else {
		require.NoError(t, err)
	}
	assert.Equal(t, step.Result, got)
}
