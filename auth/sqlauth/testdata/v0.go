// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package testdata

var v0 = &DBState{
	SQL: `CREATE TABLE records (
		encryption_key_hash bytea NOT NULL,
		created_at timestamp with time zone NOT NULL,
		public boolean NOT NULL,
		satellite_address text NOT NULL,
		macaroon_head bytea NOT NULL,
		expires_at timestamp with time zone,
		encrypted_secret_key bytea NOT NULL,
		encrypted_access_grant bytea NOT NULL,
		invalid_reason text,
		invalid_at timestamp with time zone,
		PRIMARY KEY ( encryption_key_hash )
	);`,
}
