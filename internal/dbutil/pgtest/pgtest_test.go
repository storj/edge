// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package pgtest_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"storj.io/common/testcontext"
	"storj.io/edge/internal/dbutil/pgtest"
)

func TestOpenUnique(t *testing.T) {
	connstr := pgtest.PickPostgres(t)
	ctx := testcontext.New(t)
	defer ctx.Cleanup()
	db, err := pgtest.OpenUnique(ctx, connstr, "testdb")
	require.NoError(t, err)
	defer ctx.Check(db.Close)
	require.NoError(t, db.PingContext(ctx))
	_, err = db.ExecContext(ctx, `CREATE TABLE t (id int)`)
	require.NoError(t, err)
}
