// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package sqlauth_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"storj.io/common/testcontext"
	"storj.io/gateway-mt/pkg/auth/sqlauth"
	"storj.io/gateway-mt/pkg/auth/sqlauth/testdata"
	"storj.io/private/dbutil/dbschema"
	"storj.io/private/dbutil/pgtest"
	"storj.io/private/dbutil/pgutil"
	"storj.io/private/dbutil/tempdb"
)

func TestMigratePostgres(t *testing.T) {
	t.Parallel()
	migrateTest(t, pgtest.PickPostgres(t))
}

func TestMigrateCockroach(t *testing.T) {
	t.Parallel()
	migrateTest(t, pgtest.PickCockroachAlt(t))
}

func BenchmarkSetup_Postgres(b *testing.B) {
	connstr := pgtest.PickPostgres(b)
	benchmarkSetup(b, connstr)
}

func BenchmarkSetup_Cockroach(b *testing.B) {
	connstr := pgtest.PickCockroach(b)
	benchmarkSetup(b, connstr)
}

func benchmarkSetup(b *testing.B, connStr string) {
	for i := 0; i < b.N; i++ {
		func() {
			ctx := context.Background()

			kv, err := sqlauth.OpenTest(ctx, zap.NewNop(), b.Name(), connStr)
			require.NoError(b, err)
			defer func() { require.NoError(b, kv.Close()) }()

			err = kv.MigrateToLatest(ctx)
			require.NoError(b, err)
		}()
	}
}

func migrateTest(t *testing.T, connStr string) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	log := zaptest.NewLogger(t)

	kv, err := sqlauth.OpenTest(ctx, log, t.Name(), connStr)
	require.NoError(t, err)
	defer func() { require.NoError(t, kv.Close()) }()

	db := kv.TagSQL()

	dbxSchema, err := LoadSchemaFromSQL(ctx, connStr, kv.Schema())
	require.NoError(t, err)

	// get migration for this database
	migrations := kv.Migration(ctx)
	for i := range migrations.Steps {
		// the schema is different when migration step is before the step, cannot test the layout
		tag := fmt.Sprintf("#%d - v%d", i, i)

		// run migration up to a specific version
		err := migrations.TargetVersion(i).Run(ctx, log)
		require.NoError(t, err, tag)

		// find the matching expected version
		expected := testdata.States[i]

		// insert data for new tables
		if expected.NewData != "" {
			_, err := db.ExecContext(ctx, expected.NewData)
			require.NoError(t, err, tag)
		}

		// load schema from database
		schema, err := pgutil.QuerySchema(ctx, db)
		require.NoError(t, err, tag)
		// we don't care changes in versions table
		schema.DropTable("versions")

		// load data from database
		data, err := pgutil.QueryData(ctx, db, schema)
		require.NoError(t, err, tag)

		dbSnapshot, err := LoadDBSnapshot(ctx, expected, connStr)
		require.NoError(t, err, tag)

		if len(schema.Tables) == 0 {
			schema.Tables = nil
		}
		if len(schema.Indexes) == 0 {
			schema.Indexes = nil
		}

		require.Equal(t, dbSnapshot.Schema, schema, tag)
		require.Equal(t, dbSnapshot.Data, data, tag)

		// verify schema for last migration step matches expected production schema
		if i == len(migrations.Steps)-1 {
			require.Equal(t, dbSnapshot.Schema, dbxSchema, tag)
		}
	}
}

// LoadDBSnapshot converts a DBState into a DBSnapshot. It
// executes the SQL and stores the shema and data.
func LoadDBSnapshot(ctx context.Context, dbState *testdata.DBState, connstr string) (*testdata.DBSnapshot, error) {
	snapshot, err := LoadSnapshotFromSQL(ctx, connstr, fmt.Sprintf("%s\n%s", dbState.SQL, dbState.NewData))
	if err != nil {
		return nil, err
	}
	return &testdata.DBSnapshot{
		Version: dbState.Version,
		Schema:  snapshot.Schema,
		Data:    snapshot.Data,
	}, nil
}

// LoadSchemaFromSQL inserts script into connstr and loads schema.
func LoadSchemaFromSQL(ctx context.Context, connstr, script string) (_ *dbschema.Schema, err error) {
	db, err := tempdb.OpenUnique(ctx, connstr, "load-schema")
	if err != nil {
		return nil, err
	}
	defer func() { err = errs.Combine(err, db.Close()) }()

	_, err = db.ExecContext(ctx, script)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	return pgutil.QuerySchema(ctx, db)
}

// LoadSnapshotFromSQL inserts script into connstr and loads schema.
func LoadSnapshotFromSQL(ctx context.Context, connstr, script string) (_ *dbschema.Snapshot, err error) {
	db, err := tempdb.OpenUnique(ctx, connstr, "load-schema")
	if err != nil {
		return nil, errs.Wrap(err)
	}
	defer func() { err = errs.Combine(err, db.Close()) }()

	_, err = db.ExecContext(ctx, script)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	snapshot, err := pgutil.QuerySnapshot(ctx, db)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	snapshot.Sections = dbschema.NewSections(script)

	return snapshot, nil
}
