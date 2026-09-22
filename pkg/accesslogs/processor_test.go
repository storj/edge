// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package accesslogs

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
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

	log := zaptest.NewLogger(t)
	defer ctx.Check(log.Sync)

	s := noopStorage{}
	p := NewProcessor(log, Options{})
	defer ctx.Check(p.Close)

	ctx.Go(func() error { return p.Run(ctx) })

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

	require.NoError(t, p.QueueEntry(s, key1, entry1))
	require.NoError(t, p.QueueEntry(s, key2, entry1))
	require.NoError(t, p.QueueEntry(s, key1, entry2))
	require.NoError(t, p.QueueEntry(s, key2, entry2))
	require.NoError(t, p.QueueEntry(s, key1, entry3))
	require.NoError(t, p.QueueEntry(s, key2, entry3))

	for _, key := range []any{key1, key2} {
		v, ok := p.parcels.Load(key)
		require.True(t, ok)
		parcel := v.(*parcel)
		require.Equal(t, "entry1\nentry2\nentry3\n", parcel.current.String())
	}
}

func TestProcessorWithShipment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		shipmentLimit     memory.Size
		expectedShipments int
	}{
		{
			name:              "small shipment limit",
			shipmentLimit:     20 * memory.B,
			expectedShipments: 10,
		},
		{
			name:              "big shipment limit",
			shipmentLimit:     63 * memory.MiB,
			expectedShipments: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := testcontext.New(t)

			log := zaptest.NewLogger(t)
			defer ctx.Check(log.Sync)

			s := newInMemoryStorage()
			p := NewProcessor(log, Options{
				DefaultShipmentLimit:    tc.shipmentLimit,
				DefaultShipmentInterval: time.Hour,
			})
			defer ctx.Check(p.Close)

			ctx.Go(func() error { return p.Run(ctx) })

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

			for range 10 {
				require.NoError(t, p.QueueEntry(s, key1, entry1))
				require.NoError(t, p.QueueEntry(s, key2, entry1))
				require.NoError(t, p.QueueEntry(s, key1, entry2))
				require.NoError(t, p.QueueEntry(s, key2, entry2))
			}

			require.NoError(t, p.Close()) // sync, don't wait until the deferred call

			for _, bucket := range []string{key1.Bucket, key2.Bucket} {
				buf := bytes.NewBuffer(nil)

				require.Len(t, s.getBucketContents(bucket), tc.expectedShipments)

				for _, v := range s.getBucketContents(bucket) {
					buf.Write(v)
				}

				bucketContents := buf.String()
				require.Equal(t, 20, strings.Count(bucketContents, "\n"))
				bucketContents = strings.Replace(bucketContents, entry1.String()+"\n", "", 10)
				bucketContents = strings.Replace(bucketContents, entry2.String()+"\n", "", 10)
				require.Empty(t, bucketContents)
			}
		})
	}
}

func TestProcessorWithInterval(t *testing.T) {
	t.Parallel()

	ctx := testcontext.New(t)

	log := zaptest.NewLogger(t)
	defer ctx.Check(log.Sync)

	s := &tsInMemoryStorage{}
	p := NewProcessor(log, Options{
		DefaultShipmentLimit:    63 * memory.MiB,
		DefaultShipmentInterval: 100 * time.Millisecond,
	})
	defer ctx.Check(p.Close)

	ctx.Go(func() error { return p.Run(ctx) })

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

	for range 10 {
		require.NoError(t, p.QueueEntry(s, key1, entry1))
		require.NoError(t, p.QueueEntry(s, key2, entry1))
		require.NoError(t, p.QueueEntry(s, key1, entry2))
		require.NoError(t, p.QueueEntry(s, key2, entry2))
	}

	for done, i := false, 0; !done; time.Sleep(100 * time.Millisecond) {
		require.NotEqual(t, i, 10, "exceeded 10 iterations")
		for _, bucket := range []string{key1.Bucket, key2.Bucket} {
			buf := bytes.NewBuffer(nil)

			if len(s.getBucketContents(bucket)) != 1 {
				continue
			}

			for _, v := range s.getBucketContents(bucket) {
				buf.Write(v)
			}

			bucketContents := buf.String()

			if strings.Count(bucketContents, "\n") != 20 {
				continue
			}

			bucketContents = strings.Replace(bucketContents, entry1.String()+"\n", "", 10)
			bucketContents = strings.Replace(bucketContents, entry2.String()+"\n", "", 10)

			done = len(bucketContents) == 0
			i++
		}
	}
}

type tsInMemoryStorage struct {
	mu sync.Mutex
	s  *inMemoryStorage
}

func (s *tsInMemoryStorage) getBucketContents(bucket string) map[string][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.s == nil {
		s.s = newInMemoryStorage()
	}

	return s.s.getBucketContents(bucket)
}

func (s *tsInMemoryStorage) Put(_ context.Context, bucket, key string, body []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.s == nil {
		s.s = newInMemoryStorage()
	}
	return s.s.Put(context.Background(), bucket, key, body)
}

func TestRandomKey(t *testing.T) {
	now := time.Date(2019, time.February, 6, 0, 0, 38, 0, time.UTC)
	for _, p := range []string{
		"prefix",
		"prefix/",
	} {
		k, err := randomKey(p, now)
		require.NoError(t, err)
		require.Regexp(t, "^"+p+"2019-02-06-00-00-38-[0-9A-F]{16}$", k)
	}
}

var exampleAmazonS3ServerAccessLogLine = func() func() string {
	var i atomic.Int64
	i.Store(-1)
	exampleLogLines := []string{
		`79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be DOC-EXAMPLE-BUCKET1 [06/Feb/2019:00:00:38 +0000] 192.0.2.3 79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be 3E57427F3EXAMPLE REST.GET.VERSIONING - "GET /DOC-EXAMPLE-BUCKET1?versioning HTTP/1.1" 200 - 113 - 7 - "-" "S3Console/0.4" - s9lzHYrFp76ZVxRcpX9+5cjAnEH2ROuNkd2BHfIa6UkFVdtjf5mKR3/eTPFvsiP/XV/VLi31234= SigV4 ECDHE-RSA-AES128-GCM-SHA256 AuthHeader DOC-EXAMPLE-BUCKET1.s3.us-west-1.amazonaws.com TLSV1.2 arn:aws:s3:us-west-1:123456789012:accesspoint/example-AP Yes`,
		`79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be DOC-EXAMPLE-BUCKET1 [06/Feb/2019:00:00:38 +0000] 192.0.2.3 79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be 891CE47D2EXAMPLE REST.GET.LOGGING_STATUS - "GET /DOC-EXAMPLE-BUCKET1?logging HTTP/1.1" 200 - 242 - 11 - "-" "S3Console/0.4" - 9vKBE6vMhrNiWHZmb2L0mXOcqPGzQOI5XLnCtZNPxev+Hf+7tpT6sxDwDty4LHBUOZJG96N1234= SigV4 ECDHE-RSA-AES128-GCM-SHA256 AuthHeader DOC-EXAMPLE-BUCKET1.s3.us-west-1.amazonaws.com TLSV1.2 - -`,
		`79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be DOC-EXAMPLE-BUCKET1 [06/Feb/2019:00:00:38 +0000] 192.0.2.3 79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be A1206F460EXAMPLE REST.GET.BUCKETPOLICY - "GET /DOC-EXAMPLE-BUCKET1?policy HTTP/1.1" 404 NoSuchBucketPolicy 297 - 38 - "-" "S3Console/0.4" - BNaBsXZQQDbssi6xMBdBU2sLt+Yf5kZDmeBUP35sFoKa3sLLeMC78iwEIWxs99CRUrbS4n11234= SigV4 ECDHE-RSA-AES128-GCM-SHA256 AuthHeader DOC-EXAMPLE-BUCKET1.s3.us-west-1.amazonaws.com TLSV1.2 - Yes `,
		`79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be DOC-EXAMPLE-BUCKET1 [06/Feb/2019:00:01:00 +0000] 192.0.2.3 79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be 7B4A0FABBEXAMPLE REST.GET.VERSIONING - "GET /DOC-EXAMPLE-BUCKET1?versioning HTTP/1.1" 200 - 113 - 33 - "-" "S3Console/0.4" - Ke1bUcazaN1jWuUlPJaxF64cQVpUEhoZKEG/hmy/gijN/I1DeWqDfFvnpybfEseEME/u7ME1234= SigV4 ECDHE-RSA-AES128-GCM-SHA256 AuthHeader DOC-EXAMPLE-BUCKET1.s3.us-west-1.amazonaws.com TLSV1.2 - -`,
		`79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be DOC-EXAMPLE-BUCKET1 [06/Feb/2019:00:01:57 +0000] 192.0.2.3 79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be DD6CC733AEXAMPLE REST.PUT.OBJECT s3-dg.pdf "PUT /DOC-EXAMPLE-BUCKET1/s3-dg.pdf HTTP/1.1" 200 - - 4406583 41754 28 "-" "S3Console/0.4" - 10S62Zv81kBW7BB6SX4XJ48o6kpcl6LPwEoizZQQxJd5qDSCTLX0TgS37kYUBKQW3+bPdrg1234= SigV4 ECDHE-RSA-AES128-SHA AuthHeader DOC-EXAMPLE-BUCKET1.s3.us-west-1.amazonaws.com TLSV1.2 - Yes `,
	}
	return func() string {
		n := i.Add(1)
		return exampleLogLines[n%int64(len(exampleLogLines))]
	}
}()

func BenchmarkParallelQueueEntry(b *testing.B) {
	benchmarkParallelQueueEntry(b, 0)
}

func BenchmarkParallelQueueEntryWithTimedFlush(b *testing.B) {
	benchmarkParallelQueueEntry(b, time.Millisecond)
}

func benchmarkParallelQueueEntry(b *testing.B, interval time.Duration) {
	ctx := testcontext.New(b)

	log := zap.NewNop()
	defer ctx.Check(log.Sync)

	s := noopStorage{}
	p := NewProcessor(log, Options{DefaultShipmentInterval: interval})
	defer ctx.Check(p.Close)

	ctx.Go(func() error { return p.Run(ctx) })

	id, err := uuid.New()
	require.NoError(b, err)

	key := Key{
		PublicProjectID: id,
		Bucket:          "bucket",
		Prefix:          "prefix",
	}

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			require.NoError(b, p.QueueEntry(s, key, newTestEntry(exampleAmazonS3ServerAccessLogLine())))
		}
	})
}

func BenchmarkQueueEntry(b *testing.B) {
	benchmarkQueueEntry(b, 0)
}

func BenchmarkQueueEntryWithTimedFlush(b *testing.B) {
	benchmarkQueueEntry(b, time.Millisecond)
}

func benchmarkQueueEntry(b *testing.B, interval time.Duration) {
	ctx := testcontext.New(b)

	log := zap.NewNop()
	defer ctx.Check(log.Sync)

	s := noopStorage{}
	p := NewProcessor(log, Options{DefaultShipmentInterval: interval})
	defer ctx.Check(p.Close)

	ctx.Go(func() error { return p.Run(ctx) })

	id, err := uuid.New()
	require.NoError(b, err)

	key := Key{
		PublicProjectID: id,
		Bucket:          "bucket",
		Prefix:          "prefix",
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		require.NoError(b, p.QueueEntry(s, key, newTestEntry(exampleAmazonS3ServerAccessLogLine())))
	}
}

var (
	benchmarkRandomKeyResult    string
	benchmarkUniqueStringResult string
)

func BenchmarkRandomKey(b *testing.B) {
	var (
		r   string
		err error
	)
	for i := 0; i < b.N; i++ {
		r, err = randomKey("prefix", time.Now())
		require.NoError(b, err)
	}
	benchmarkRandomKeyResult = r
}

func BenchmarkUniqueString(b *testing.B) {
	var (
		r   string
		err error
	)
	for i := 0; i < b.N; i++ {
		r, err = uniqueString()
		require.NoError(b, err)
	}
	benchmarkUniqueStringResult = r
}

// TestProcessorCloseBoundedByShutdownTimeout covers Close flushing into a full
// upload queue while run is wedged in Put: the flush blocks before the
// uploader's own shutdown timeout is armed, so Close has to bound it itself.
func TestProcessorCloseBoundedByShutdownTimeout(t *testing.T) {
	t.Parallel()

	ctx := testcontext.New(t)

	log := zaptest.NewLogger(t)
	defer ctx.Check(log.Sync)

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	opts := Options{
		DefaultShipmentLimit:    63 * memory.MiB,
		DefaultShipmentInterval: time.Hour,
	}
	opts.UploadingOptions.QueueLimit = 1
	opts.UploadingOptions.ShutdownTimeout = 100 * time.Millisecond

	s := blockingStorage{started: make(chan struct{}, 1)}
	p := NewProcessor(log, opts)

	done := make(chan error, 1)
	ctx.Go(func() error {
		done <- p.Run(runCtx)
		return nil
	})

	// Close flushes three parcels: the first wedges run in Put, the second
	// fills the queue, and the third blocks on the full queue.
	for i := range 3 {
		id, err := uuid.New()
		require.NoError(t, err)
		key := Key{PublicProjectID: id, Bucket: "bucket", Prefix: strconv.Itoa(i)}
		require.NoError(t, p.QueueEntry(s, key, newTestEntry("entry")))
	}

	require.ErrorIs(t, p.Close(), context.DeadlineExceeded)

	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}
