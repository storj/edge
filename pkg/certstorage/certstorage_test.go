// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package certstorage

import (
	"io/fs"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/stretchr/testify/require"
	"github.com/zeebo/errs"
	"go.uber.org/zap/zaptest"

	"storj.io/common/testcontext"
	"storj.io/common/testrand"
	"storj.io/edge/pkg/internal/gcstest"
	"storj.io/edge/pkg/internal/s3test"
)

func TestGCS(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	gcs := newGCS(ctx, t)
	testLocker(ctx, t, gcs)
	testStorage(ctx, t, gcs)
}

func TestS3(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	s := newS3(ctx, t)
	testLocker(ctx, t, s)
	testStorage(ctx, t, s)
}

func testLocker(ctx *testcontext.Context, t *testing.T, locker certmagic.Locker) {
	a, b := gcstest.RandPathUTF8(gcstest.PathLengthLimit), gcstest.RandPathUTF8(gcstest.PathLengthLimit)
	require.NoError(t, locker.Lock(ctx, a))
	require.NoError(t, locker.Lock(ctx, b))
	defer ctx.Check(func() error { return locker.Unlock(ctx, b) })

	// best effort: there's no guarantee this happens concurrently and not
	// sequentially.
	var beforeUnlock atomic.Uint32
	ctx.Go(func() error {
		require.True(t, beforeUnlock.CompareAndSwap(0, 1))
		require.NoError(t, locker.Unlock(ctx, a))
		return nil
	})

	require.NoError(t, locker.Lock(ctx, a))
	defer ctx.Check(func() error { return locker.Unlock(ctx, a) })
	require.True(t, beforeUnlock.CompareAndSwap(1, 0))
}

func testStorage(ctx *testcontext.Context, t *testing.T, storage certmagic.Storage) {
	prefix := gcstest.RandPathUTF8(gcstest.PathLengthLimit - 5)
	name := prefix + "/test"
	lock := prefix + "/lock"

	require.NoError(t, storage.Lock(ctx, lock))
	defer ctx.Check(func() error { return storage.Unlock(ctx, lock) }) // ensure a clean state after a failure

	require.NoError(t, storage.Store(ctx, name, testrand.Bytes(9)))
	defer func() { _ = storage.Delete(ctx, name) }() // ensure a clean state after a failure

	require.True(t, storage.Exists(ctx, name))

	keyInfo, err := storage.Stat(ctx, name)
	require.NoError(t, err)

	require.True(t, keyInfo.IsTerminal)
	require.Equal(t, name, keyInfo.Key)
	require.WithinDuration(t, time.Now(), keyInfo.Modified, time.Minute)
	require.EqualValues(t, 9, keyInfo.Size)

	list, err := storage.List(ctx, prefix, true)
	require.NoError(t, err)

	expectedList := []string{name, lock}
	sort.Strings(expectedList)
	require.Equal(t, expectedList, list)

	b, err := storage.Load(ctx, name)
	require.NoError(t, err)

	require.Len(t, b, 9)

	require.NoError(t, storage.Delete(ctx, name))

	require.False(t, storage.Exists(ctx, gcstest.RandPathUTF8(gcstest.PathLengthLimit)))
	_, err = storage.Stat(ctx, name)
	require.ErrorIs(t, err, fs.ErrNotExist)
	_, err = storage.Load(ctx, name)
	require.ErrorIs(t, err, fs.ErrNotExist)
	require.ErrorIs(t, storage.Delete(ctx, name), fs.ErrNotExist)
}

func newGCS(ctx *testcontext.Context, t *testing.T) *GCS {
	jsonKey, bucket, err := gcstest.FindCredentials()
	if errs.Is(err, gcstest.ErrCredentialsNotFound) {
		t.Skipf("Skipping %s without credentials/bucket provided", t.Name())
	}

	logger := zaptest.NewLogger(t)
	defer ctx.Check(logger.Sync)

	gcs, err := NewGCS(ctx, logger.Named("storage"), jsonKey, bucket)
	require.NoError(t, err)

	return gcs
}

func newS3(ctx *testcontext.Context, t *testing.T) *S3 {
	cfg, err := s3test.FindCredentials()
	if s3test.ErrCredentialsNotFound.Has(err) {
		t.Skipf("Skipping %s without credentials/bucket provided", t.Name())
	}

	logger := zaptest.NewLogger(t)
	defer ctx.Check(logger.Sync)

	s, err := NewS3(ctx, logger.Named("storage"), S3Options{
		Bucket:          cfg.Bucket,
		Region:          cfg.Region,
		AccessKeyID:     cfg.AccessKeyID,
		SecretAccessKey: cfg.SecretAccessKey,
		Endpoint:        cfg.Endpoint,
	})
	require.NoError(t, err)

	return s
}
