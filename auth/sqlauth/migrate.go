// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package sqlauth

import (
	"context"

	"storj.io/private/migrate"
	"storj.io/private/tagsql"
)

// Migration returns table migrations.
// The SQL here represent the step-wise changes to the database.
func (d *KV) Migration(ctx context.Context) *migrate.Migration {
	d.db.DB = &RebindableTagSQL{DB: d.db.DB, rebind: d.db.Rebind}
	return &migrate.Migration{
		Table: "versions",
		Steps: []*migrate.Step{
			{
				DB:          &d.db.DB,
				Description: "Initial setup",
				Version:     0,
				Action: migrate.SQL{
					`CREATE TABLE records (
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
				},
			},
		},
	}
}

// RebindableTagSQL offers a version of tagsql.DB which exposed a SQL Rebind() method.
type RebindableTagSQL struct {
	tagsql.DB
	rebind func(sql string) string
}

// Rebind allows rewrites SQL parameter syntax as required in Migration.Run().
func (db RebindableTagSQL) Rebind(sql string) string {
	return db.rebind(sql)
}
