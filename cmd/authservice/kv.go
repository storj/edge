// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"context"
	"net/url"

	"github.com/zeebo/errs"

	"storj.io/gateway-mt/auth"
	"storj.io/gateway-mt/auth/memauth"
	"storj.io/gateway-mt/auth/sqlauth"
	"storj.io/private/dbutil/pgutil"
)

func openKV(ctx context.Context, kvurl string) (auth.KV, error) {
	// ensure connection string is present for monkit / tagsql
	kvurl, err := pgutil.CheckApplicationName(kvurl, "authservice")
	if err != nil {
		return nil, err
	}

	parsed, err := url.Parse(kvurl)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	if parsed.Scheme == "memory" {
		return memauth.New(), nil
	}

	return sqlauth.OpenKV(ctx, kvurl)
}
