// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package auth

import (
	"context"

	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/gateway-mt/pkg/auth/authdb"
	"storj.io/gateway-mt/pkg/auth/badgerauth"
	"storj.io/gateway-mt/pkg/auth/badgerauth/badgerauthmigration"
	"storj.io/gateway-mt/pkg/auth/memauth"
	"storj.io/gateway-mt/pkg/auth/sqlauth"
	"storj.io/private/dbutil"
)

// OpenKV opens the database connection with the appropriate driver.
func OpenKV(ctx context.Context, log *zap.Logger, config Config) (_ authdb.KV, err error) {
	defer mon.Task()(&ctx)(&err)

	driver, _, _, err := dbutil.SplitConnStr(config.KVBackend)
	if err != nil {
		return nil, err
	}

	switch driver {
	case "memory":
		return memauth.New(), nil
	case "pgxcockroach", "postgres", "cockroach", "pgx":
		return sqlauth.Open(ctx, log, config.KVBackend, sqlauth.Options{
			ApplicationName: "authservice",
		})
	case "badger":
		kv, err := badgerauth.New(log, config.Node)
		if err != nil {
			return nil, err
		}
		if config.NodeMigration.SourceSQLAuthKVBackend != "" {
			src, err := sqlauth.Open(ctx, log, config.NodeMigration.SourceSQLAuthKVBackend, sqlauth.Options{
				ApplicationName: "authservice (sqlauth->badgerauth migration)",
			})
			if err != nil {
				return nil, err
			}
			return badgerauthmigration.New(log, src, kv, config.NodeMigration), nil
		}
		return kv, nil
	default:
		return nil, errs.New("unknown scheme: %q", config.KVBackend)
	}
}
