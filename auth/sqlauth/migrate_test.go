// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package sqlauth

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/zeebo/errs"
	"go.uber.org/zap/zaptest"

	"storj.io/common/testcontext"
	"storj.io/gateway-mt/auth/sqlauth/testdata"
	"storj.io/private/dbutil"
	"storj.io/private/dbutil/cockroachutil"
	"storj.io/private/dbutil/dbschema"
	"storj.io/private/dbutil/pgtest"
	"storj.io/private/dbutil/pgutil"
	"storj.io/private/dbutil/tempdb"
)

func TestMigratePostgres(t *testing.T) { migrateTest(t, pgtest.PickPostgres(t)) }

func TestMigrateCockroach(t *testing.T) { migrateTest(t, pgtest.PickCockroachAlt(t)) }

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

			tempDB, err := OpenUnique(ctx, connStr, "migrate")
			require.NoError(b, err)
			defer func() { require.NoError(b, tempDB.Close()) }()
			kv := &KV{db: tempDB}

			err = kv.MigrateToLatest(ctx)
			require.NoError(b, err)
		}()
	}
}

// OpenUnique opens a temporary, uniquely named database (or isolated database schema)
// for scratch work. When closed, this database or schema will be cleaned up and destroyed.
// This function is a hybrid of dbutil.OpenUnique() and sqlauth.Open().
func OpenUnique(ctx context.Context, connURL string, namePrefix string) (db *DB, err error) {
	// ensure connection string is present for monkit / tagsql
	connURL, err = pgutil.CheckApplicationName(connURL, "gateway-mt-migration-test")
	if err != nil {
		return nil, err
	}
	var tempDB *dbutil.TempDatabase
	if strings.HasPrefix(connURL, "postgres://") || strings.HasPrefix(connURL, "postgresql://") {
		tempDB, err = pgutil.OpenUnique(ctx, connURL, namePrefix)
	} else if strings.HasPrefix(connURL, "cockroach://") {
		tempDB, err = cockroachutil.OpenUnique(ctx, connURL, namePrefix)
	} else {
		return nil, unsupportedDriver(connURL)
	}
	if err != nil {
		return nil, err
	}
	if err := tempDB.Ping(ctx); err != nil {
		return nil, makeErr(err)
	}

	db = &DB{DB: tempDB.DB}
	db.Hooks.Now = time.Now
	if strings.HasPrefix(connURL, "postgres://") || strings.HasPrefix(connURL, "postgresql://") || strings.HasPrefix(connURL, "cockroach://") {
		db.dbMethods = newpgxcockroach(db)
	} else {
		return nil, unsupportedDriver(connURL)
	}
	return db, nil
}

func migrateTest(t *testing.T, connStr string) {
	t.Parallel()
	ctx := testcontext.New(t)
	defer ctx.Cleanup()
	log := zaptest.NewLogger(t)

	db, err := OpenUnique(ctx, connStr, "load-schema")
	defer func() { require.NoError(t, db.Close()) }()
	require.NoError(t, err)
	kv := &KV{db: db}

	dbxSchema, err := LoadSchemaFromSQL(ctx, connStr, db.Schema())
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
			_, err := db.DB.ExecContext(ctx, expected.NewData)
			require.NoError(t, err, tag)
		}

		// load schema from database
		schema, err := pgutil.QuerySchema(ctx, db.DB)
		require.NoError(t, err, tag)
		// we don't care changes in versions table
		schema.DropTable("versions")

		// load data from database
		data, err := pgutil.QueryData(ctx, db.DB, schema)
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
