// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package auth

import (
	"context"

	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/edge/internal/dbutil"
	"storj.io/edge/pkg/auth/authdb"
	"storj.io/edge/pkg/auth/badgerauth"
	"storj.io/edge/pkg/auth/spannerauth"
	"storj.io/edge/pkg/auth/spannerauth/spannerauthmigration"
)

// OpenStorage opens the underlying storage for Auth Service's database,
// determining the backend based on the connection string.
func OpenStorage(ctx context.Context, log *zap.Logger, config Config) (_ authdb.Storage, err error) {
	defer mon.Task()(&ctx)(&err)

	driver, _, _, err := dbutil.SplitConnStr(config.KVBackend)
	if err != nil {
		return nil, err
	}

	switch driver {
	case "badger":
		return badgerauth.New(log, config.Node)
	case "spanner":
		return spannerauth.Open(ctx, log, config.Spanner)
	case "spannermigration":
		src, err := badgerauth.New(log, config.Node)
		if err != nil {
			return nil, err
		}
		dst, err := spannerauth.Open(ctx, log, config.Spanner)
		if err != nil {
			return nil, errs.Combine(err, src.Close())
		}
		return spannerauthmigration.New(log, src, dst), nil
	default:
		return nil, errs.New("unknown scheme: %q", config.KVBackend)
	}
}
