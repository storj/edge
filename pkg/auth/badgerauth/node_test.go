// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauth_test

import (
	"testing"
	"time"

	badger "github.com/outcaste-io/badger/v3"
	"github.com/stretchr/testify/assert"

	"storj.io/common/testcontext"
	"storj.io/gateway-mt/pkg/auth/authdb"
	"storj.io/gateway-mt/pkg/auth/badgerauth"
	"storj.io/gateway-mt/pkg/auth/badgerauth/badgerauthtest"
)

// TODO(artur): current tests provide decent coverage, but some important
// verification is still missing:
//  - testing the internal state of the database
//  - more complex scenarios (#162)

func TestDeleteUnusedAlwaysReturnsError(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	var err error

	badgerauthtest.RunSingleNode(t, 24*time.Hour, func(ctx *testcontext.Context, t *testing.T, db *badger.DB, node *badgerauth.Node) {
		_, _, _, err = node.DeleteUnused(ctx, 0, 0, 0)
		assert.Error(t, err)
		_, _, _, err = node.DeleteUnused(ctx, 24*time.Hour, 10000, 1000)
		assert.Error(t, err)
	})

	//nolint: dogsled
	_, _, _, err = badgerauth.Node{}.DeleteUnused(ctx, 0, 0, 0)
	assert.Error(t, err)
	//nolint: dogsled
	_, _, _, err = badgerauth.Node{}.DeleteUnused(ctx, 24*time.Hour, 10000, 1000)
	assert.Error(t, err)
}

// TestBasicCycle tests basic create → invalidate → delete single record
// lifecycle sequentially, verifying fundamental KV interface guarantees.
func TestBasicCycle(t *testing.T) {
	keyHash := authdb.KeyHash{'t', 'e', 's', 't'}
	record := &authdb.Record{
		SatelliteAddress:     "test",
		MacaroonHead:         []byte{'t', 'e', 's', 't'},
		EncryptedSecretKey:   []byte{'t', 'e', 's', 't'},
		EncryptedAccessGrant: []byte{'t', 'e', 's', 't'},
		Public:               true,
	}

	badgerauthtest.RunSingleNode(t, time.Hour, func(ctx *testcontext.Context, t *testing.T, db *badger.DB, node *badgerauth.Node) {
		// put
		badgerauthtest.Put{
			KeyHash: keyHash,
			Record:  record,
		}.Check(ctx, t, node)
		// put again
		badgerauthtest.Put{
			KeyHash: keyHash,
			Record:  record,
			Error:   badgerauth.Error.New("key already exists"),
		}.Check(ctx, t, node)
		// get unknown record
		badgerauthtest.Get{
			KeyHash: authdb.KeyHash{1},
		}.Check(ctx, t, node)
		// get
		badgerauthtest.Get{
			KeyHash: keyHash,
			Result:  record,
		}.Check(ctx, t, node)
		// get again
		badgerauthtest.Get{
			KeyHash: keyHash,
			Result:  record,
		}.Check(ctx, t, node)
		// invalidate unknown record
		badgerauthtest.Invalidate{
			KeyHash: authdb.KeyHash{2},
			Reason:  "test",
		}.Check(ctx, t, node)
		// invalidate
		badgerauthtest.Invalidate{
			KeyHash: keyHash,
			Reason:  "test",
		}.Check(ctx, t, node)
		// invalidate again
		badgerauthtest.Invalidate{
			KeyHash: keyHash,
			Reason:  "a different reason",
		}.Check(ctx, t, node)
		// get after invalidation
		badgerauthtest.Get{
			KeyHash: keyHash,
			Error:   badgerauth.Error.Wrap(authdb.Invalid.New("test")),
		}.Check(ctx, t, node)
		// delete unknown record
		badgerauthtest.Delete{
			KeyHash: authdb.KeyHash{3},
		}.Check(ctx, t, node)
		// delete
		badgerauthtest.Delete{
			KeyHash: keyHash,
		}.Check(ctx, t, node)
		// delete again
		badgerauthtest.Delete{
			KeyHash: keyHash,
		}.Check(ctx, t, node)
		// get after deletion
		badgerauthtest.Get{
			KeyHash: keyHash,
		}.Check(ctx, t, node)
	})
}

// TestBasicCycleWithSafeExpiration is like TestBasicCycle, but it focuses on
// the behavior of actions when the record has a safe (>=tombstoneExpiration)
// expiration time.
func TestBasicCycleWithSafeExpiration(t *testing.T) {
	// construct current time used in this test so that it is stripped of the
	// number of nanoseconds and the monotonic clock reading.
	now := time.Unix(time.Now().Unix(), 0)
	day := 24 * time.Hour
	expiresAt := now.Add(day)

	keyHash := authdb.KeyHash{'t', 'e', 's', 't'}
	record := &authdb.Record{
		SatelliteAddress:     "test",
		MacaroonHead:         []byte{'t', 'e', 's', 't'},
		EncryptedSecretKey:   []byte{'t', 'e', 's', 't'},
		EncryptedAccessGrant: []byte{'t', 'e', 's', 't'},
		ExpiresAt:            &expiresAt,
		Public:               true,
	}

	testBasicCycleWithExpiration(t, now, day, day, keyHash, record)
}

// TestBasicCycleWithUnsafeExpiration is like TestBasicCycle, but it focuses on
// the behavior of actions when the record has an unsafe expiration time.
func TestBasicCycleWithUnsafeExpiration(t *testing.T) {
	// Construct current time used in this test so that it is stripped of the
	// number of nanoseconds and the monotonic clock reading.
	now := time.Unix(time.Now().Unix(), 0)
	day := 24 * time.Hour
	// One second is an unsafe expiration time.
	expiresAt := now.Add(time.Second)

	keyHash := authdb.KeyHash{'t', 'e', 's', 't'}
	record := &authdb.Record{
		SatelliteAddress:     "test",
		MacaroonHead:         []byte{'t', 'e', 's', 't'},
		EncryptedSecretKey:   []byte{'t', 'e', 's', 't'},
		EncryptedAccessGrant: []byte{'t', 'e', 's', 't'},
		ExpiresAt:            &expiresAt,
		Public:               true,
	}

	testBasicCycleWithExpiration(t, now, time.Second, day, keyHash, record)
}

func testBasicCycleWithExpiration(t *testing.T, now time.Time, expiration, tombstoneExpiration time.Duration, keyHash authdb.KeyHash, record *authdb.Record) {
	badgerauthtest.RunSingleNode(t, tombstoneExpiration, func(ctx *testcontext.Context, t *testing.T, db *badger.DB, node *badgerauth.Node) {
		// first put
		badgerauthtest.PutAtTime{
			KeyHash: keyHash,
			Record:  record,
			Time:    now,
		}.Check(ctx, t, node)
		// first get
		getExhaustively(ctx, t, node, badgerauthtest.GetAtTime{
			KeyHash: keyHash,
			Result:  record,
			Time:    now,
		}, expiration)
		// invalidate
		badgerauthtest.InvalidateAtTime{
			KeyHash: keyHash,
			Reason:  "test",
			Time:    now,
		}.Check(ctx, t, node)
		// get after invalidation
		getExhaustively(ctx, t, node, badgerauthtest.GetAtTime{
			KeyHash: keyHash,
			Error:   badgerauth.Error.Wrap(authdb.Invalid.New("test")),
			Time:    now,
		}, expiration)
		// delete
		badgerauthtest.DeleteAtTime{
			KeyHash: keyHash,
			Time:    now,
		}.Check(ctx, t, node)
		// get after deletion
		getExhaustively(ctx, t, node, badgerauthtest.GetAtTime{
			KeyHash: keyHash,
			Time:    now,
		}, expiration)
	})
}

// getExhaustively produces more badgerauthtest.GetAtTime checks that are
// borderline cases around expiration.
func getExhaustively(ctx *testcontext.Context, t *testing.T, node *badgerauth.Node, check badgerauthtest.GetAtTime, expiration time.Duration) {
	check.Check(ctx, t, node) // include submitted check

	badgerauthtest.GetAtTime{
		KeyHash: check.KeyHash,
		Result:  check.Result,
		Error:   check.Error,
		Time:    check.Time.Add(expiration - 1),
	}.Check(ctx, t, node)

	badgerauthtest.GetAtTime{
		KeyHash: check.KeyHash,
		Result:  check.Result,
		Error:   check.Error,
		Time:    check.Time.Add(expiration),
	}.Check(ctx, t, node)

	badgerauthtest.GetAtTime{
		KeyHash: check.KeyHash,
		Time:    check.Time.Add(expiration + 1),
	}.Check(ctx, t, node)
}
