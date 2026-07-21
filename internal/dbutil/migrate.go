// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package dbutil

import (
	"context"
	"database/sql"
	"fmt"
	"hash/fnv"

	"github.com/zeebo/errs"
	"go.uber.org/zap"
)

// Step is a single versioned migration step.
type Step struct {
	Version     int
	Description string
	SQL         []string
}

// Migration is an ordered set of migration steps tracked in Table.
type Migration struct {
	Table string
	Steps []Step
}

// Run applies all steps with Version greater than the current schema version.
//
// Run serializes concurrent callers (e.g. multiple service replicas starting
// at once) with a PostgreSQL session-level advisory lock derived from Table, so
// simultaneous migrators wait for one another instead of racing on the versions
// table. Because session advisory locks are bound to the connection that took
// them, the entire run is pinned to a single *sql.Conn.
func (m *Migration) Run(ctx context.Context, log *zap.Logger, db *sql.DB) (err error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return errs.Wrap(err)
	}
	defer func() { err = errs.Combine(err, conn.Close()) }()

	lockID := advisoryLockID(m.Table)
	if _, err = conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, lockID); err != nil {
		return errs.Wrap(err)
	}
	defer func() {
		_, unlockErr := conn.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, lockID)
		err = errs.Combine(err, errs.Wrap(unlockErr))
	}()

	if _, err = conn.ExecContext(ctx, fmt.Sprintf(
		`CREATE TABLE IF NOT EXISTS %s (version int NOT NULL, description text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (version))`,
		m.Table)); err != nil {
		return errs.Wrap(err)
	}

	var current sql.NullInt64
	if err = conn.QueryRowContext(ctx, fmt.Sprintf(`SELECT max(version) FROM %s`, m.Table)).Scan(&current); err != nil {
		return errs.Wrap(err)
	}

	for _, step := range m.Steps {
		if current.Valid && int(current.Int64) >= step.Version {
			continue
		}
		log.Info("applying migration", zap.Int("version", step.Version), zap.String("description", step.Description))
		if err = runStep(ctx, conn, m.Table, step); err != nil {
			return errs.Wrap(err)
		}
	}
	return nil
}

func runStep(ctx context.Context, conn *sql.Conn, table string, step Step) (err error) {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			err = errs.Combine(err, tx.Rollback())
		}
	}()
	for _, stmt := range step.SQL {
		if _, err = tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, fmt.Sprintf(`INSERT INTO %s (version, description) VALUES ($1, $2)`, table), step.Version, step.Description); err != nil {
		return err
	}
	return tx.Commit()
}

// advisoryLockID derives a stable 64-bit key for pg_advisory_lock from the
// migration table name, namespaced to avoid colliding with advisory locks
// taken elsewhere against the same database.
func advisoryLockID(table string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("storj.io/edge/internal/dbutil:" + table))
	return int64(h.Sum64())
}
