// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package dbutil_test

import (
	"database/sql"
	"sync"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/testcontext"
	"storj.io/edge/internal/dbutil"
	"storj.io/edge/internal/dbutil/pgtest"
)

func TestMigrationRun(t *testing.T) {
	connstr := pgtest.PickPostgres(t)
	ctx := testcontext.New(t)
	defer ctx.Cleanup()
	db, err := sql.Open("pgx", connstr)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	// clean slate
	_, _ = db.ExecContext(ctx, `DROP TABLE IF EXISTS widgets; DROP TABLE IF EXISTS test_versions;`)

	m := &dbutil.Migration{
		Table: "test_versions",
		Steps: []dbutil.Step{{Version: 0, Description: "create widgets", SQL: []string{
			`CREATE TABLE widgets (id int PRIMARY KEY)`,
		}}},
	}
	log := zaptest.NewLogger(t)
	require.NoError(t, m.Run(ctx, log, db))
	// second run is a no-op (table already exists; would error if re-applied)
	require.NoError(t, m.Run(ctx, log, db))

	var n int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM test_versions`).Scan(&n))
	require.Equal(t, 1, n)
}

// TestMigrationRunConcurrent verifies the advisory lock serializes concurrent
// migrators: without it, simultaneous runs would collide on the CREATE TABLE
// and the version-row PK. All runs must succeed and the step must apply once.
func TestMigrationRunConcurrent(t *testing.T) {
	connstr := pgtest.PickPostgres(t)
	ctx := testcontext.New(t)
	defer ctx.Cleanup()
	db, err := sql.Open("pgx", connstr)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	// clean slate
	_, _ = db.ExecContext(ctx, `DROP TABLE IF EXISTS conc_widgets; DROP TABLE IF EXISTS conc_versions;`)

	m := &dbutil.Migration{
		Table: "conc_versions",
		Steps: []dbutil.Step{{Version: 0, Description: "create conc_widgets", SQL: []string{
			`CREATE TABLE conc_widgets (id int PRIMARY KEY)`,
		}}},
	}
	log := zaptest.NewLogger(t)

	const n = 5
	var wg sync.WaitGroup
	results := make(chan error, n)
	for range n {
		wg.Go(func() {
			results <- m.Run(ctx, log, db)
		})
	}
	wg.Wait()
	close(results)
	for e := range results {
		require.NoError(t, e)
	}

	var applied int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM conc_versions`).Scan(&applied))
	require.Equal(t, 1, applied)
}
