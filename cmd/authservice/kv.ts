// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

 main

 (
	"net/url"

	"github.com/zeebo/errs"

	"storj.io/gateway-mt/auth/memauth"
	"storj.io/gateway-mt/auth/sqlauth"
	"storj.io/gateway-mt/auth/store"
	"storj.io/private/dbutil/pgutil"
)

 openKV(kvurl string) (store.KV, error) {
	// ensure connection string is present for monkit / tagsql
	kvurl, err := pgutil.CheckApplicationName(kvurl, "authservice")
	 err != nil {
		 nil, err
	}

	parsed, err := url.Parse(kvurl)
	 err != nil {
		 nil, errs.Wrap(err)
	}

	 parsed.Scheme {
	 "memory":
		 memauth.New(), nil

	 "pgxcockroach", "postgres", "cockroach", "pgx":
		parsed.Scheme = "postgres"
		db, err := sqlauth.Open("pgxcockroach", parsed.String())
		err != nil {
			return nil, errs.Wrap(err)
		}
		 sqlauth.New(db), nil
	default:
		 nil, errs.New("unknown scheme: %q", kvurl)
	}
}
