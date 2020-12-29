// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"net/url"

	"github.com/zeebo/errs"

	"storj.io/gateway-mt/auth"
	"storj.io/gateway-mt/auth/memauth"
	"storj.io/gateway-mt/auth/sqlauth"
)

func openKV(kvurl string) (auth.KV, error) {
	parsed, err := url.Parse(kvurl)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	switch parsed.Scheme {
	case "memory":
		return memauth.New(), nil

	case "pgxcockroach":
		parsed.Scheme = "postgres"
		db, err := sqlauth.Open("pgxcockroach", parsed.String())
		if err != nil {
			return nil, errs.Wrap(err)
		}
		return sqlauth.New(db), nil

	case "sqlite3":
		parsed.Scheme = "file"
		db, err := sqlauth.Open("sqlite3", parsed.String())
		if err != nil {
			return nil, errs.Wrap(err)
		}
		return sqlauth.New(db), nil

	default:
		return nil, errs.New("unknown scheme: %q", kvurl)
	}
}
