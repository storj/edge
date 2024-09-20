// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauthtest

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"storj.io/common/testcontext"
	"storj.io/edge/pkg/auth/badgerauth"
)

// Run tests against a single badgerauth.(*DB).
func Run(t *testing.T, parallel bool, config badgerauth.Config, fn func(ctx *testcontext.Context, t *testing.T, log *zap.Logger, db *badgerauth.DB)) {
	if parallel {
		t.Parallel()
	}

	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	setConfigDefaults(&config)

	log := zaptest.NewLogger(t).Named("badgerauth")
	defer ctx.Check(log.Sync)

	db, err := badgerauth.Open(log, config)
	require.NoError(t, err)
	defer ctx.Check(db.Close)

	require.NoError(t, db.HealthCheck(ctx), "HealthCheck")

	fn(ctx, t, log, db)
}

func setConfigDefaults(config *badgerauth.Config) {
	config.FirstStart = true

	if config.ConflictBackoff.Max == 0 {
		config.ConflictBackoff.Max = 5 * time.Minute
	}
	if config.ConflictBackoff.Min == 0 {
		config.ConflictBackoff.Min = 100 * time.Millisecond
	}
}
