// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package auth

import (
	"context"

	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/gateway-mt/auth/authdb"
	"storj.io/gateway-mt/auth/memauth"
	"storj.io/gateway-mt/auth/sqlauth"
	"storj.io/private/dbutil"
)

// OpenKV opens the database connection with the appropriate driver.
func OpenKV(ctx context.Context, log *zap.Logger, kvurl string) (authdb.KV, error) {
	driver, _, _, err := dbutil.SplitConnStr(kvurl)
	if err != nil {
		return nil, err
	}

	switch driver {
	case "memory":
		return memauth.New(), nil

	case "pgxcockroach", "postgres", "cockroach", "pgx":
		kv, err := sqlauth.Open(ctx, log, kvurl, sqlauth.Options{
			ApplicationName: "authservice",
		})
		return kv, err
	default:
		return nil, errs.New("unknown scheme: %q", kvurl)
	}
}
