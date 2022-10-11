// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package gcslock

import (
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zeebo/errs"

	"storj.io/common/sync2"
	"storj.io/common/testcontext"
)

func TestMutex_PutHeadPatchDeleteCycle(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	mu := newMutex(ctx, t)
	// 1st put should succeed
	resp, err := mu.put(ctx)
	require.NoError(t, err)
	_, err = sync2.Copy(ctx, io.Discard, resp.Body)
	require.NoError(t, errs.Combine(err, resp.Body.Close()))
	require.Equal(t, http.StatusOK, resp.StatusCode)
	// 2nd put should fail
	resp, err = mu.put(ctx)
	require.NoError(t, err)
	_, err = sync2.Copy(ctx, io.Discard, resp.Body)
	require.NoError(t, errs.Combine(err, resp.Body.Close()))
	require.Equal(t, http.StatusPreconditionFailed, resp.StatusCode)

	resp, err = mu.head(ctx)
	require.NoError(t, err)
	_, err = sync2.Copy(ctx, io.Discard, resp.Body)
	require.NoError(t, errs.Combine(err, resp.Body.Close()))
	require.True(t, mu.shouldWait(ctx, resp.StatusCode, resp.Header))

	require.NoError(t, mu.refresh(ctx))

	resp, err = mu.delete(ctx, "1")
	require.NoError(t, err)
	_, err = sync2.Copy(ctx, io.Discard, resp.Body)
	require.NoError(t, errs.Combine(err, resp.Body.Close()))
	require.Equal(t, http.StatusPreconditionFailed, resp.StatusCode)

	resp, err = mu.delete(ctx, mu.lastKnownMetageneration)
	require.NoError(t, err)
	_, err = sync2.Copy(ctx, io.Discard, resp.Body)
	require.NoError(t, errs.Combine(err, resp.Body.Close()))
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
}

func TestMutex_LockUnlock(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	mu := newMutex(ctx, t)

	for i := 0; i < 3; i++ {
		require.NoError(t, mu.Lock(ctx))
		require.NoError(t, mu.Unlock(ctx))
	}

	t.Run("unlock of unlocked mutex", func(t *testing.T) {
		require.Error(t, mu.Unlock(ctx))
	})
}

func newMutex(ctx *testcontext.Context, t *testing.T) *Mutex {
	pathToJsonKey := os.Getenv("STORJ_TEST_PATH_TO_JSON_KEY")

	if pathToJsonKey == "" {
		// TODO(artur): tests should run a mock GCS without credentials provided.
		t.Skipf("Skipping %s without credentials provided", t.Name())
	}

	jsonKey, err := os.ReadFile(pathToJsonKey)
	require.NoError(t, err)

	m, err := NewDefaultMutex(ctx, jsonKey, "test", "gcslock_test")
	require.NoError(t, err)

	return m
}
