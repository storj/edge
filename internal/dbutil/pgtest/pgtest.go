// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package pgtest

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	// stdlib used indirectly.
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/zeebo/errs"
)

var counter atomic.Int64

// PickPostgres returns the test Postgres connection string or skips the test.
// It skips when STORJ_TEST_POSTGRES is unset or set to "omit" (the convention
// used across the Storj CI to disable a database backend for a test run).
func PickPostgres(t testing.TB) string {
	connstr := os.Getenv("STORJ_TEST_POSTGRES")
	if connstr == "" || connstr == "omit" {
		t.Skip("STORJ_TEST_POSTGRES not set; skipping Postgres test")
	}
	return connstr
}

// DB is a temporary database that drops itself on Close.
type DB struct {
	*sql.DB
	ConnStr string
	name    string
	admin   string
}

// OpenUnique creates a uniquely-named database on the server in connstr.
func OpenUnique(ctx context.Context, connstr, prefix string) (*DB, error) {
	name := fmt.Sprintf("%s_%d_%d", sanitize(prefix), os.Getpid(), counter.Add(1))

	admin, err := sql.Open("pgx", connstr)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	defer func() { _ = admin.Close() }()

	if _, err = admin.ExecContext(ctx, `CREATE DATABASE `+quoteIdent(name)); err != nil {
		return nil, errs.Wrap(err)
	}

	uniqueConnStr, err := withDatabase(connstr, name)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	db, err := sql.Open("pgx", uniqueConnStr)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return &DB{DB: db, ConnStr: uniqueConnStr, name: name, admin: connstr}, nil
}

// Close drops the temporary database.
func (db *DB) Close() (err error) {
	err = db.DB.Close()
	admin, aerr := sql.Open("pgx", db.admin)
	if aerr != nil {
		return errs.Combine(err, aerr)
	}
	defer func() { err = errs.Combine(err, admin.Close()) }()
	_, derr := admin.Exec(`DROP DATABASE IF EXISTS ` + quoteIdent(db.name)) // nolint:noctx
	return errs.Combine(err, derr)
}

func withDatabase(connstr, name string) (string, error) {
	u, err := url.Parse(connstr)
	if err != nil {
		return "", err
	}
	u.Path = "/" + name
	return u.String(), nil
}

func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return '_'
		}
	}, s)
}
