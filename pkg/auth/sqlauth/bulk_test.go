// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package sqlauth_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/testcontext"
	"storj.io/common/testrand"
	"storj.io/edge/internal/dbutil/pgtest"
	"storj.io/edge/pkg/auth/authdb"
	"storj.io/edge/pkg/auth/sqlauth"
)

func TestBulkWriter(t *testing.T) {
	connstr := pgtest.PickPostgres(t)
	ctx := testcontext.New(t)
	defer ctx.Cleanup()
	kv, err := sqlauth.OpenTest(ctx, zaptest.NewLogger(t), t.Name(), connstr)
	require.NoError(t, err)
	defer ctx.Check(kv.Close)
	require.NoError(t, kv.MigrateToLatest(ctx))

	// a pre-existing, already-invalidated record: the bulk writer must not
	// touch it even if a stale (still-valid) copy of it appears in a batch.
	var existingKH authdb.KeyHash
	testrand.Read(existingKH[:])
	existingRec := newRecord()
	require.NoError(t, kv.Put(ctx, existingKH, existingRec))
	require.NoError(t, kv.Invalidate(ctx, existingKH, "revoked"))
	before, err := kv.GetFullRecord(ctx, existingKH)
	require.NoError(t, err)
	require.NotNil(t, before)

	writer, err := kv.NewBulkWriter(ctx)
	require.NoError(t, err)
	defer ctx.Check(writer.Close)

	const n = 100
	keyHashes := make([]authdb.KeyHash, 0, n+1)
	records := make([]*authdb.FullRecord, 0, n+1)
	for range n {
		var kh authdb.KeyHash
		testrand.Read(kh[:])
		keyHashes = append(keyHashes, kh)
		records = append(records, &authdb.FullRecord{Record: *newRecord(), CreatedAt: time.Now().UTC()})
	}
	// a stale copy of the existing (invalidated) key, as a backfill from a
	// source that doesn't know about the destination's invalidation would see it.
	keyHashes = append(keyHashes, existingKH)
	records = append(records, &authdb.FullRecord{Record: *existingRec, CreatedAt: time.Now().UTC()})

	require.NoError(t, writer.BulkPutFullRecords(ctx, keyHashes, records))
	// re-running the identical batch must be a no-op, not an error.
	require.NoError(t, writer.BulkPutFullRecords(ctx, keyHashes, records))

	for i, kh := range keyHashes[:n] {
		got, err := kv.GetFullRecord(ctx, kh)
		require.NoError(t, err)
		require.NotNil(t, got)
		require.Equal(t, records[i].SatelliteAddress, got.SatelliteAddress)
	}

	after, err := kv.GetFullRecord(ctx, existingKH)
	require.NoError(t, err)
	require.Equal(t, before, after, "pre-existing invalidated record must be untouched")
}

// TestBulkWriterConnectionReuse verifies that a second BulkWriter can be created
// after closing the first one on the same KV, even if the physical connection is
// reused (temp-table collision fix: IF NOT EXISTS + TRUNCATE).
func TestBulkWriterConnectionReuse(t *testing.T) {
	connstr := pgtest.PickPostgres(t)
	ctx := testcontext.New(t)
	defer ctx.Cleanup()
	kv, err := sqlauth.OpenTest(ctx, zaptest.NewLogger(t), t.Name(), connstr)
	require.NoError(t, err)
	defer ctx.Check(kv.Close)
	require.NoError(t, kv.MigrateToLatest(ctx))

	// First BulkWriter: create, add records, close.
	writer1, err := kv.NewBulkWriter(ctx)
	require.NoError(t, err)

	var kh1 authdb.KeyHash
	testrand.Read(kh1[:])
	rec1 := &authdb.FullRecord{Record: *newRecord(), CreatedAt: time.Now().UTC()}

	require.NoError(t, writer1.BulkPutFullRecords(ctx, []authdb.KeyHash{kh1}, []*authdb.FullRecord{rec1}))
	require.NoError(t, writer1.Close())

	// Verify first record was stored.
	got1, err := kv.GetFullRecord(ctx, kh1)
	require.NoError(t, err)
	require.NotNil(t, got1)

	// Second BulkWriter: must succeed even if reusing the same physical connection.
	writer2, err := kv.NewBulkWriter(ctx)
	require.NoError(t, err)
	defer ctx.Check(writer2.Close)

	var kh2 authdb.KeyHash
	testrand.Read(kh2[:])
	rec2 := &authdb.FullRecord{Record: *newRecord(), CreatedAt: time.Now().UTC()}

	// This must not fail with "relation already exists".
	require.NoError(t, writer2.BulkPutFullRecords(ctx, []authdb.KeyHash{kh2}, []*authdb.FullRecord{rec2}))

	// Verify second record was stored correctly.
	got2, err := kv.GetFullRecord(ctx, kh2)
	require.NoError(t, err)
	require.NotNil(t, got2)
	require.Equal(t, rec2.SatelliteAddress, got2.SatelliteAddress)
}

// TestBulkPutFullRecordsRejectsCommaInUsageTags verifies that BulkPutFullRecords
// rejects records with commas in usage tags (consistent with Put/PutFullRecord).
func TestBulkPutFullRecordsRejectsCommaInUsageTags(t *testing.T) {
	connstr := pgtest.PickPostgres(t)
	ctx := testcontext.New(t)
	defer ctx.Cleanup()
	kv, err := sqlauth.OpenTest(ctx, zaptest.NewLogger(t), t.Name(), connstr)
	require.NoError(t, err)
	defer ctx.Check(kv.Close)
	require.NoError(t, kv.MigrateToLatest(ctx))

	writer, err := kv.NewBulkWriter(ctx)
	require.NoError(t, err)
	defer ctx.Check(writer.Close)

	// Create records where one has a tag with a comma.
	keyHashes := make([]authdb.KeyHash, 2)
	records := make([]*authdb.FullRecord, 2)
	testrand.Read(keyHashes[0][:])
	testrand.Read(keyHashes[1][:])

	// First record: valid tags.
	rec1 := newRecord()
	rec1.UsageTags = []string{"tag1", "tag2"}
	records[0] = &authdb.FullRecord{Record: *rec1, CreatedAt: time.Now().UTC()}

	// Second record: invalid tag with comma.
	rec2 := newRecord()
	rec2.UsageTags = []string{"tag3", "tag,with,commas"}
	records[1] = &authdb.FullRecord{Record: *rec2, CreatedAt: time.Now().UTC()}

	// BulkPutFullRecords should reject the entire batch.
	err = writer.BulkPutFullRecords(ctx, keyHashes, records)
	require.Error(t, err)
	require.Contains(t, err.Error(), "usage tags can't contain commas")

	// Verify no rows from this batch were written.
	got0, err := kv.GetFullRecord(ctx, keyHashes[0])
	require.NoError(t, err)
	require.Nil(t, got0, "first record must not be written if batch fails")

	got1, err := kv.GetFullRecord(ctx, keyHashes[1])
	require.NoError(t, err)
	require.Nil(t, got1, "second record must not be written if batch fails")
}
