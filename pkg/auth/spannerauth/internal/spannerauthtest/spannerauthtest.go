// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package spannerauthtest

import (
	"context"

	database "cloud.google.com/go/spanner/admin/database/apiv1"
	"cloud.google.com/go/spanner/admin/database/apiv1/databasepb"
	"cloud.google.com/go/spanner/spannertest"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/gateway-mt/pkg/auth/spannerauth"
)

// Error is the error class for this package.
var Error = errs.Class("spannerauthtest")

// ConfigureTestServer returns an initialized test server, emulating Cloud
// Spanner locally.
func ConfigureTestServer(ctx context.Context, logger *zap.Logger) (*spannertest.Server, error) {
	server, err := spannertest.NewServer("localhost:0")
	if err != nil {
		return nil, Error.Wrap(err)
	}
	server.SetLogger(func(format string, args ...interface{}) {
		logger.Sugar().Debugf(format, args...)
	})

	a, err := database.NewDatabaseAdminClient(ctx, spannerauth.EmulatorOpts(server.Addr)...)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	defer func() {
		err = Error.Wrap(errs.Combine(err, a.Close()))
	}()
	// Reference:
	// https://cloud.google.com/spanner/docs/reference/standard-sql/data-definition-language
	o, err := a.UpdateDatabaseDdl(ctx, &databasepb.UpdateDatabaseDdlRequest{
		Statements: []string{
			`CREATE TABLE records (
				encryption_key_hash    BYTES(32)   NOT NULL,
				created_at             TIMESTAMP   NOT NULL DEFAULT (CURRENT_TIMESTAMP()),
				public                 BOOL        NOT NULL,
				satellite_address      STRING(MAX) NOT NULL,
				macaroon_head          BYTES(MAX)  NOT NULL,
				expires_at             TIMESTAMP,
				encrypted_secret_key   BYTES(32)   NOT NULL,
				encrypted_access_grant BYTES(MAX)  NOT NULL,
				invalidation_reason    STRING(MAX),
				invalidated_at         TIMESTAMP
			) PRIMARY KEY (encryption_key_hash),
			ROW DELETION POLICY (OLDER_THAN(expires_at, INTERVAL 0 DAY))`,
		},
	})
	if err != nil {
		return nil, err
	}
	return server, o.Wait(ctx)
}
