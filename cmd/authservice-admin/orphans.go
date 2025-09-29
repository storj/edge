// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"cloud.google.com/go/spanner"
	"cloud.google.com/go/spanner/apiv1/spannerpb"
	"github.com/zeebo/clingy"
	"github.com/zeebo/errs"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"

	"storj.io/edge/internal/authadminclient"
)

type cmdRemoveOrphans struct {
	authClientConfig authadminclient.Config
	satelliteID      string
	satelliteDB      string
	satelliteDBCreds string
	dryRun           bool
}

func (cmd *cmdRemoveOrphans) Setup(params clingy.Parameters) {
	cmd.authClientConfig = getAuthAdminClientConfig(params)
	cmd.dryRun = params.Flag("dry-run", "show how many records would be affected without making changes", false,
		clingy.Transform(strconv.ParseBool), clingy.Boolean,
	).(bool)

	cmd.satelliteID = params.Flag("satellite-id", "satellite ID/address", "").(string)
	cmd.satelliteDB = params.Flag("satellite-db", "satellite database name", "").(string)
	cmd.satelliteDBCreds = params.Flag("satellite-db-creds", "satellite database credentials file", "").(string)
}

func (cmd *cmdRemoveOrphans) Execute(ctx context.Context) error {
	if cmd.satelliteID == "" || cmd.satelliteDB == "" || cmd.satelliteDBCreds == "" {
		return errs.New("satellite-id, satellite-db, and satellite-db-creds must all be configured")
	}

	authClient, err := spanner.NewClientWithConfig(ctx, cmd.authClientConfig.Spanner.DatabaseName,
		spanner.ClientConfig{DisableNativeMetrics: true}, option.WithCredentialsFile(cmd.authClientConfig.Spanner.CredentialsFilename))
	if err != nil {
		return errs.New("connect to auth database: %w", err)
	}
	defer authClient.Close()

	macaroonHeads, readTimestamp, err := cmd.collectMacaroonHeads(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Found %v macaroonHeads in %v\n", len(macaroonHeads), cmd.satelliteDB)

	totalCount, orphanCount, err := cmd.countRecords(ctx, authClient, macaroonHeads, readTimestamp)
	if err != nil {
		return err
	}

	if cmd.dryRun {
		fmt.Printf("Would invalidate %d orphaned records out of %d total records\n",
			orphanCount, totalCount)
		return nil
	}

	if totalCount == 0 || orphanCount == 0 {
		return errs.New("Found 0 records to invalidate, address: %v db: %v", cmd.satelliteID, cmd.authClientConfig.Spanner.DatabaseName)
	}

	if totalCount > 0 && orphanCount == totalCount {
		return errs.New("refusing to invalidate all %d of %d records - wrong satellite ID?\n",
			orphanCount, totalCount)
	}

	return cmd.removeOrphans(ctx, authClient, macaroonHeads, readTimestamp, orphanCount, totalCount)
}

func (cmd *cmdRemoveOrphans) collectMacaroonHeads(ctx context.Context) ([][]byte, time.Time, error) {
	client, err := spanner.NewClientWithConfig(ctx, cmd.satelliteDB,
		spanner.ClientConfig{DisableNativeMetrics: true}, option.WithCredentialsFile(cmd.satelliteDBCreds))
	if err != nil {
		return nil, time.Time{}, errs.New("connect to satellite: %w", err)
	}
	defer client.Close()

	txn := client.Single().WithTimestampBound(spanner.ExactStaleness(60 * time.Second))
	iter := txn.Query(ctx, spanner.Statement{SQL: `SELECT head FROM api_keys`})
	defer iter.Stop()

	var heads [][]byte
	for {
		row, err := iter.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, time.Time{}, errs.New("query satellite api_keys: %w", err)
		}

		var head []byte
		if err := row.Column(0, &head); err != nil {
			return nil, time.Time{}, errs.New("parse satellite row: %w", err)
		}
		heads = append(heads, head)
	}

	if len(heads) == 0 {
		return nil, time.Time{}, errs.New("no macaroon heads found from satellite")
	}

	readTimestamp, err := txn.Timestamp()
	if err != nil {
		return nil, time.Time{}, errs.New("get read timestamp: %w", err)
	}

	return heads, readTimestamp, nil
}

func (cmd *cmdRemoveOrphans) countRecords(ctx context.Context, authClient *spanner.Client, validMacaroonHeads [][]byte, readTimestamp time.Time) (totalCount, orphanCount int64, err error) {
	// Count total records for this satellite
	totalStmt := spanner.Statement{
		SQL: `SELECT COUNT(*) FROM records
		      WHERE invalidated_at IS NULL
		      AND created_at <= @read_timestamp
		      AND satellite_address = @satellite`,
		Params: map[string]interface{}{
			"read_timestamp": readTimestamp,
			"satellite":      cmd.satelliteID,
		},
	}

	err = authClient.Single().Query(ctx, totalStmt).Do(func(row *spanner.Row) error {
		return row.Column(0, &totalCount)
	})
	if err != nil {
		return 0, 0, errs.New("count total records: %w", err)
	}

	// Count orphaned records
	orphanStmt := spanner.Statement{
		SQL: `SELECT COUNT(*) FROM records
		      WHERE invalidated_at IS NULL
		      AND macaroon_head NOT IN UNNEST(@heads)
		      AND created_at <= @read_timestamp
		      AND satellite_address = @satellite`,
		Params: map[string]interface{}{
			"heads":          validMacaroonHeads,
			"read_timestamp": readTimestamp,
			"satellite":      cmd.satelliteID,
		},
	}

	err = authClient.Single().Query(ctx, orphanStmt).Do(func(row *spanner.Row) error {
		return row.Column(0, &orphanCount)
	})
	if err != nil {
		return 0, 0, errs.New("count orphaned records: %w", err)
	}

	return totalCount, orphanCount, nil
}

func (cmd *cmdRemoveOrphans) removeOrphans(ctx context.Context, authClient *spanner.Client, validMacaroonHeads [][]byte, readTimestamp time.Time, orphanCount, totalCount int64) error {
	if len(validMacaroonHeads) == 0 {
		return errs.New("validMacaroonHeads must be > 0")
	}
	expiresAt := time.Now().AddDate(0, 1, 0)
	stmt := spanner.Statement{
		SQL: `UPDATE records
		      SET invalidated_at = CURRENT_TIMESTAMP(),
		          invalidation_reason = @reason,
		          expires_at = @expires_at
		      WHERE invalidated_at IS NULL
		      AND macaroon_head NOT IN UNNEST(@heads)
		      AND created_at <= @read_timestamp
		      AND satellite_address = @satellite`,
		Params: map[string]interface{}{
			"reason":         "orphan cleanup " + readTimestamp.Format(time.RFC3339),
			"expires_at":     expiresAt,
			"heads":          validMacaroonHeads,
			"read_timestamp": readTimestamp,
			"satellite":      cmd.satelliteID,
		},
	}
	opts := spanner.QueryOptions{
		Priority: spannerpb.RequestOptions_PRIORITY_LOW,
	}
	// Use a longer timeout for large updates - partitioned updates can take a while
	// Set low priority to avoid impacting production workload
	updateCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	rowsAffected, err := authClient.PartitionedUpdateWithOptions(updateCtx, stmt, opts)
	if err != nil {
		return errs.New("update orphaned records: %w", err)
	}

	fmt.Printf("Invalidated %d orphaned records out of %d total records (%.1f%%) (expiration: %s)\n",
		rowsAffected, totalCount, 100.0*float64(rowsAffected)/float64(totalCount), expiresAt.Format(time.RFC3339))
	return nil
}
