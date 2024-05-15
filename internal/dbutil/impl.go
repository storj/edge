// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package dbutil

// Implementation type of valid DBs.
type Implementation int

const (
	// Unknown is an unknown db type.
	Unknown Implementation = iota
	// Postgres is a Postgresdb type.
	Postgres
	// Cockroach is a Cockroachdb type.
	Cockroach
	// Bolt is a Bolt kv store.
	Bolt
	// Redis is a Redis kv store.
	Redis
	// SQLite3 is a sqlite3 database.
	SQLite3
)

// ImplementationForScheme returns the Implementation that is used for
// the url with the provided scheme.
func ImplementationForScheme(scheme string) Implementation {
	switch scheme {
	case "pgx", "postgres", "postgresql":
		return Postgres
	case "cockroach":
		return Cockroach
	case "bolt":
		return Bolt
	case "redis":
		return Redis
	case "sqlite", "sqlite3":
		return SQLite3
	default:
		return Unknown
	}
}
