// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"net/url"

	"github.com/zeebo/errs"

	"storj.io/stargate/auth"
	"storj.io/stargate/auth/memauth"
	"storj.io/stargate/auth/sqlauth"
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
		db, err := sqlauth.Open("pgxcockroach", kvurl)
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
