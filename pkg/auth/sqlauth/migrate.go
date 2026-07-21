// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package sqlauth

import (
	"context"

	"go.uber.org/zap"

	"storj.io/edge/internal/dbutil"
)

// MigrateToLatest creates/updates the schema to the latest version.
func (d *KV) MigrateToLatest(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	migration := &dbutil.Migration{
		Table: "versions",
		Steps: []dbutil.Step{
			{
				Version:     0,
				Description: "Initial setup",
				SQL: []string{
					`CREATE TABLE records (
						encryption_key_hash    bytea       NOT NULL,
						created_at             timestamptz NOT NULL,
						public                 boolean     NOT NULL,
						public_project_id      bytea,
						satellite_address      text        NOT NULL,
						macaroon_head          bytea       NOT NULL,
						expires_at             timestamptz,
						encrypted_secret_key   bytea       NOT NULL,
						encrypted_access_grant bytea       NOT NULL,
						invalidation_reason    text,
						invalidated_at         timestamptz,
						usage_tags             text,
						project_created_at     timestamptz,
						PRIMARY KEY ( encryption_key_hash )
					)`,
				},
			},
		},
	}
	return Error.Wrap(migration.Run(ctx, zap.L().Named("migrate"), d.underlyingDB()))
}
