// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package accesslogs

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/memory"
	"storj.io/common/testcontext"
	"storj.io/common/uuid"
)

type testEntry struct {
	content string
}

func (e testEntry) Size() memory.Size {
	return memory.Size(len(e.content))
}

func (e testEntry) String() string {
	return e.content
}

func newTestEntry(s string) testEntry {
	return testEntry{
		content: s,
	}
}

func TestProcessor(t *testing.T) {
	t.Parallel()

	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	log := zaptest.NewLogger(t)
	defer ctx.Check(log.Sync)

	p := NewProcessor(log, noopStorage{}, Options{})
	defer ctx.Check(p.Close)

	ctx.Go(func() error {
		return p.Run(ctx)
	})

	uuid1, err := uuid.New()
	require.NoError(t, err)
	uuid2, err := uuid.New()
	require.NoError(t, err)
	key1 := Key{
		PublicProjectID: uuid1,
		Bucket:          "bucket1",
		Prefix:          "prefix1",
	}
	key2 := Key{
		PublicProjectID: uuid2,
		Bucket:          "bucket2",
		Prefix:          "prefix2/",
	}
	entry1 := newTestEntry("entry1")
	entry2 := newTestEntry("entry2")
	entry3 := newTestEntry("entry3")

	require.NoError(t, p.QueueEntry(nil, key1, entry1))
	require.NoError(t, p.QueueEntry(nil, key2, entry1))
	require.NoError(t, p.QueueEntry(nil, key1, entry2))
	require.NoError(t, p.QueueEntry(nil, key2, entry2))
	require.NoError(t, p.QueueEntry(nil, key1, entry3))
	require.NoError(t, p.QueueEntry(nil, key2, entry3))

	for _, key := range []any{key1, key2} {
		v, ok := p.parcels.Load(key)
		require.True(t, ok)
		parcel := v.(*parcel)
		require.Equal(t, "entry1\nentry2\nentry3\n", parcel.current.String())
	}
}

func TestProcessorWithShipment(t *testing.T) {
	t.Parallel()

	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	log := zaptest.NewLogger(t)
	defer ctx.Check(log.Sync)

	s := newInMemoryStorage()
	p := NewProcessor(log, s, Options{
		DefaultShipmentLimit: 20 * memory.B,
	})
	defer ctx.Check(p.Close)

	ctx.Go(func() error {
		return p.Run(ctx)
	})

	uuid1, err := uuid.New()
	require.NoError(t, err)
	uuid2, err := uuid.New()
	require.NoError(t, err)
	key1 := Key{
		PublicProjectID: uuid1,
		Bucket:          "bucket1",
		Prefix:          "prefix1",
	}
	key2 := Key{
		PublicProjectID: uuid2,
		Bucket:          "bucket2",
		Prefix:          "prefix2/",
	}
	entry1 := newTestEntry("entry1")
	entry2 := newTestEntry("entry2")

	for i := 0; i < 10; i++ {
		require.NoError(t, p.QueueEntry(nil, key1, entry1))
		require.NoError(t, p.QueueEntry(nil, key2, entry1))
		require.NoError(t, p.QueueEntry(nil, key1, entry2))
		require.NoError(t, p.QueueEntry(nil, key2, entry2))
	}

	require.NoError(t, p.Close()) // sync, don't wait until the deferred call

	for _, bucket := range []string{key1.Bucket, key2.Bucket} {
		buf := bytes.NewBuffer(nil)

		for _, v := range s.getBucketContents(bucket) {
			buf.Write(v)
		}

		bucketContents := buf.String()
		require.Equal(t, 20, strings.Count(bucketContents, "\n"))
		bucketContents = strings.Replace(bucketContents, entry1.String()+"\n", "", 10)
		bucketContents = strings.Replace(bucketContents, entry2.String()+"\n", "", 10)
		require.Empty(t, bucketContents)
	}
}
