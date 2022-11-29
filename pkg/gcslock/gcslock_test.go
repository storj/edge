// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package gcslock

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/testcontext"
	"storj.io/gateway-mt/pkg/gcslock/gcsops"
)

func TestMutex_PutHeadPatchDeleteCycle(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	mu := newMutex(ctx, t)
	// 1st put should succeed & 2nd put should fail
	require.NoError(t, mu.put(ctx))
	require.ErrorIs(t, mu.put(ctx), gcsops.ErrPreconditionFailed)

	require.True(t, mu.shouldWait(ctx))

	require.NoError(t, mu.refresh(ctx))

	require.ErrorIs(t, mu.delete(ctx, "1"), gcsops.ErrPreconditionFailed)
	require.NoError(t, mu.delete(ctx, mu.lastKnownMetageneration))
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
		t.Skipf("Skipping %s without credentials provided", t.Name())
	}

	jsonKey, err := os.ReadFile(pathToJsonKey)
	require.NoError(t, err)

	logger := zaptest.NewLogger(t)
	defer ctx.Check(logger.Sync)

	m, err := NewMutex(ctx, Options{
		JSONKey: jsonKey,
		Name:    "test",
		Bucket:  "gcslock_test",
		Logger:  logger.Named("distributed lock").Sugar(),
	})
	require.NoError(t, err)

	return m
}
