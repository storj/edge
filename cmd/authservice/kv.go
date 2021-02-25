// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"net/url"

	"github.com/zeebo/errs"

	"storj.io/gateway-mt/auth"
	"storj.io/gateway-mt/auth/memauth"
	"storj.io/gateway-mt/auth/sqlauth"
	"storj.io/private/dbutil/pgutil"
)

func openKV(kvurl string) (auth.KV, error) {
	// ensure connection string is present for monkit / tagsql
	kvurl, err := pgutil.CheckApplicationName(kvurl, "authservice")
	if err != nil {
		return nil, err
	}

	parsed, err := url.Parse(kvurl)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	switch parsed.Scheme {
	case "memory":
		return memauth.New(), nil

	case "pgxcockroach", "postgres", "cockroach", "pgx":
		parsed.Scheme = "postgres"
		db, err := sqlauth.Open("pgxcockroach", parsed.String())
		if err != nil {
			return nil, errs.Wrap(err)
		}
		return sqlauth.New(db), nil
	default:
		return nil, errs.New("unknown scheme: %q", kvurl)
	}
}
