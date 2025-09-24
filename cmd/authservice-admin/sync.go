// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"cloud.google.com/go/spanner"
	"github.com/zeebo/clingy"
	"github.com/zeebo/errs"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"

	"storj.io/edge/internal/authadminclient"
)

const sampleInterval = 1000

type cmdRecordSync struct {
	authClientConfig     authadminclient.Config
	satelliteID          string
	satelliteDBName      string
	satelliteDBCredsFile string
	dryRun               bool
}

func (cmd *cmdRecordSync) Setup(params clingy.Parameters) {
	cmd.authClientConfig = getAuthAdminClientConfig(params)
	cmd.satelliteID = params.Flag("satellite-id", "satellite ID", "").(string)
	cmd.satelliteDBName = params.Flag("satellite-db", "satellite database name", "").(string)
	cmd.satelliteDBCredsFile = params.Flag("satellite-db-creds", "satellite credentials file", "").(string)
	cmd.dryRun = params.Flag("dry-run", "show changes without applying", false,
		clingy.Transform(strconv.ParseBool), clingy.Boolean,
	).(bool)
}

func (cmd *cmdRecordSync) Execute(ctx context.Context) error {
	if cmd.satelliteID == "" || cmd.satelliteDBName == "" || cmd.satelliteDBCredsFile == "" {
		return errs.New("satellite-id, satellite-db, and satellite-creds are required")
	}

	satelliteClient, err := spanner.NewClientWithConfig(ctx, cmd.satelliteDBName,
		spanner.ClientConfig{DisableNativeMetrics: true}, option.WithCredentialsFile(cmd.satelliteDBCredsFile))
	if err != nil {
		return errs.New("connect to satellite: %w", err)
	}
	defer satelliteClient.Close()

	authClient, err := spanner.NewClientWithConfig(ctx, cmd.authClientConfig.Spanner.DatabaseName,
		spanner.ClientConfig{DisableNativeMetrics: true}, option.WithCredentialsFile(cmd.authClientConfig.Spanner.CredentialsFilename))
	if err != nil {
		return errs.New("connect to authDB: %w", err)
	}
	defer authClient.Close()

	records, err := cmd.findRecords(ctx, authClient)
	if err != nil {
		return err
	}

	if len(records) == 0 {
		fmt.Println("No records to sync")
		return nil
	}

	fmt.Printf("Found %d records missing public_project_id\n", len(records))

	if cmd.dryRun {
		return cmd.showPreview(ctx, satelliteClient, records)
	}

	return cmd.syncRecords(ctx, satelliteClient, authClient, records)
}

type syncRecord struct {
	Hash         []byte
	MacaroonHead []byte
}

func (cmd *cmdRecordSync) findRecords(ctx context.Context, client *spanner.Client) ([]syncRecord, error) {
	stmt := spanner.Statement{
		SQL: `SELECT encryption_key_hash, macaroon_head FROM records
		      WHERE public_project_id IS NULL AND invalidated_at IS NULL AND
		      satellite_address = @satellite`,
		Params: map[string]interface{}{"satellite": cmd.satelliteID},
	}

	var records []syncRecord
	iter := client.Single().Query(ctx, stmt)
	defer iter.Stop()

	for {
		row, err := iter.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, errs.New("query failed: %w", err)
		}

		var r syncRecord
		if err := row.Columns(&r.Hash, &r.MacaroonHead); err != nil {
			return nil, errs.New("parse row: %w", err)
		}
		records = append(records, r)
	}

	return records, nil
}

func (cmd *cmdRecordSync) showPreview(ctx context.Context, sourceClient *spanner.Client, records []syncRecord) error {
	updated := 0
	for i, r := range records {
		publicID, err := cmd.getPublicID(ctx, sourceClient, r.MacaroonHead)
		if err != nil {
			return errs.New("getPublicProjectID failed: %w", err)
		}
		if publicID == nil {
			continue
		}
		updated++
		if i%sampleInterval == 0 {
			fmt.Printf("for macaroonHead %x would set %x\n", r.MacaroonHead, publicID)
		}
	}
	fmt.Printf("Would update %d of %d records\n", updated, len(records))
	return nil
}

func (cmd *cmdRecordSync) syncRecords(ctx context.Context, sourceClient, targetClient *spanner.Client, records []syncRecord) error {
	updated := 0
	for _, r := range records {
		publicID, err := cmd.getPublicID(ctx, sourceClient, r.MacaroonHead)
		if err != nil {
			return errs.New("getPublicProjectID failed:: %w", err)
		}
		if publicID == nil {
			continue
		}

		_, err = targetClient.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
			_, err := txn.Update(ctx, spanner.Statement{
				SQL:    `UPDATE records SET public_project_id = @public_id WHERE encryption_key_hash = @hash`,
				Params: map[string]interface{}{"public_id": publicID, "hash": r.Hash},
			})
			return err
		})
		if err != nil {
			return errs.New("syncRecords failed:: %w", err)
		}
		updated++
	}

	fmt.Printf("Updated %d of %d records\n", updated, len(records))
	return nil
}

func (cmd *cmdRecordSync) getPublicID(ctx context.Context, client *spanner.Client, macaroonHead []byte) ([]byte, error) {
	var publicID []byte
	stmt := spanner.Statement{
		SQL:    `SELECT p.public_id FROM api_keys k JOIN projects p ON p.id = k.project_id WHERE k.head = @head`,
		Params: map[string]interface{}{"head": macaroonHead},
	}

	err := client.Single().Query(ctx, stmt).Do(func(row *spanner.Row) error {
		return row.Column(0, &publicID)
	})

	return publicID, err
}
