// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package sqlmigration

import (
	"context"

	"github.com/zeebo/errs"
	"golang.org/x/sync/errgroup"

	"storj.io/edge/pkg/auth/authdb"
)

// partitionBounds splits the 32-byte key-hash space into n disjoint,
// contiguous [lo, hi) ranges covering it entirely, using single-byte prefix
// boundaries: Postgres bytea comparison is lexicographic, and a shorter
// byte string that's a prefix of a longer one sorts before it, so a 1-byte
// boundary correctly separates 32-byte hashes by their leading byte. n is
// clamped to [1, 256], since there are only 256 distinct leading-byte
// values: asking for more than 256 partitions yields exactly 256, the
// finest split this scheme can express, rather than more.
func partitionBounds(n int) [][2][]byte {
	if n > 256 {
		n = 256
	}
	if n < 1 {
		n = 1
	}
	bounds := make([][2][]byte, n)
	for i := range n {
		var lo, hi []byte
		if i > 0 {
			lo = []byte{byte(i * 256 / n)}
		}
		if i < n-1 {
			hi = []byte{byte((i + 1) * 256 / n)}
		}
		bounds[i] = [2][]byte{lo, hi}
	}
	return bounds
}

// backfill copies every record from s.src into s.dst that isn't already
// there, using Options.Concurrency parallel key-range workers.
func (s *Storage) backfill(ctx context.Context) error {
	group, groupCtx := errgroup.WithContext(ctx)

	for _, bound := range partitionBounds(s.opts.Concurrency) {
		lo, hi := bound[0], bound[1]
		group.Go(func() error {
			return s.backfillRange(groupCtx, lo, hi)
		})
	}
	return group.Wait()
}

// backfillRange backfills a single [lo, hi) key-hash partition, in batches
// of s.opts.BatchSize rows per bulk write.
func (s *Storage) backfillRange(ctx context.Context, lo, hi []byte) (err error) {
	writer, err := s.dst.NewBulkWriter(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errs.Combine(err, writer.Close()) }()

	var keyHashes []authdb.KeyHash
	var records []*authdb.FullRecord

	flush := func(ctx context.Context) error {
		if len(keyHashes) == 0 {
			return nil
		}
		if err := writer.BulkPutFullRecords(ctx, keyHashes, records); err != nil {
			return err
		}
		keyHashes = keyHashes[:0]
		records = records[:0]
		return nil
	}

	err = s.src.IterateRange(ctx, lo, hi, func(ctx context.Context, kh authdb.KeyHash, r *authdb.FullRecord) error {
		keyHashes = append(keyHashes, kh)
		records = append(records, r)
		if len(keyHashes) >= s.opts.BatchSize {
			return flush(ctx)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return flush(ctx)
}
