// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/zeebo/clingy"
	"github.com/zeebo/errs"

	"storj.io/common/storj"
	"storj.io/gateway-mt/internal/authadminclient"
	"storj.io/gateway-mt/internal/satelliteadminclient"
)

type record struct {
	AuthRecord authadminclient.Record              `json:"auth_record"`
	SatRecord  satelliteadminclient.APIKeyResponse `json:"satellite_record,omitempty"`
}

type cmdRecordShow struct {
	authClient      *authadminclient.Client
	satAdminClients map[string]*satelliteadminclient.Client
	key             string
	output          string
}

func (cmd *cmdRecordShow) Setup(params clingy.Parameters) {
	cmd.authClient = newAuthAdminClient(params)
	cmd.satAdminClients = mustSatAdminClients(params)
	cmd.output = params.Flag("output", "output format (either json or leave empty to output as text)", "", clingy.Short('o')).(string)
	cmd.key = params.Arg("key", "Access key ID or key hash").(string)
}

func (cmd *cmdRecordShow) Execute(ctx context.Context) error {
	authRecord, err := cmd.authClient.Get(ctx, cmd.key)
	if err != nil {
		return errs.New("get: %w", err)
	}

	record := record{
		AuthRecord: authRecord,
	}

	// note: APIKey is empty if the input to this command is the key hash
	// not the encryption key/access key ID. We can't decrypt it in this case.
	if cmd.satAdminClients != nil && authRecord.APIKey != "" {
		satelliteNodeURL, err := storj.ParseNodeURL(authRecord.SatelliteAddress)
		if err != nil {
			return errs.New("parse node url: %w", err)
		}

		client, ok := cmd.satAdminClients[satelliteNodeURL.Address]
		if !ok {
			return errs.New("could not find satellite admin address for %q", satelliteNodeURL.Address)
		}

		apiKeyResp, err := client.GetAPIKey(ctx, authRecord.APIKey)
		if err != nil {
			return errs.New("get api key: %w", satAPIKeyError(err))
		}

		record.SatRecord = apiKeyResp
	}

	switch cmd.output {
	case "json":
		return json.NewEncoder(os.Stdout).Encode(&record)
	default:
		printRecord(record)
		return nil
	}
}

type cmdRecordInvalidate struct {
	authClient      *authadminclient.Client
	satAdminClients map[string]*satelliteadminclient.Client
	key             string
	reason          string
}

func (cmd *cmdRecordInvalidate) Setup(params clingy.Parameters) {
	cmd.authClient = newAuthAdminClient(params)
	cmd.satAdminClients = mustSatAdminClients(params)
	cmd.key = params.Arg("key", "Access key ID or key hash").(string)
	cmd.reason = params.Arg("reason", "invalidation reason").(string)
}

func (cmd *cmdRecordInvalidate) Execute(ctx context.Context) error {
	return cmd.authClient.Invalidate(ctx, cmd.key, cmd.reason)
}

type cmdRecordUnpublish struct {
	authClient      *authadminclient.Client
	satAdminClients map[string]*satelliteadminclient.Client
	key             string
}

func (cmd *cmdRecordUnpublish) Setup(params clingy.Parameters) {
	cmd.authClient = newAuthAdminClient(params)
	cmd.satAdminClients = mustSatAdminClients(params)
	cmd.key = params.Arg("key", "Access key ID or key hash").(string)
}

func (cmd *cmdRecordUnpublish) Execute(ctx context.Context) error {
	return cmd.authClient.Unpublish(ctx, cmd.key)
}

type cmdRecordDelete struct {
	authClient      *authadminclient.Client
	satAdminClients map[string]*satelliteadminclient.Client
	key             string
	deleteAPIKey    bool
}

func (cmd *cmdRecordDelete) Setup(params clingy.Parameters) {
	cmd.authClient = newAuthAdminClient(params)
	cmd.satAdminClients = mustSatAdminClients(params)
	cmd.deleteAPIKey = params.Flag("delete-api-key", "if satellite admin addresses are configured, delete the API key on the satellite", true,
		clingy.Transform(strconv.ParseBool), clingy.Boolean,
	).(bool)
	cmd.key = params.Arg("key", "Access key ID or key hash").(string)
}

func (cmd *cmdRecordDelete) Execute(ctx context.Context) error {
	authRecord, err := cmd.authClient.Get(ctx, cmd.key)
	if err != nil {
		return errs.New("get: %w", err)
	}

	// note: APIKey is empty if the input to this command is the key hash
	// not the encryption key/access key ID. We can't decrypt it in this case.
	if cmd.satAdminClients != nil && authRecord.APIKey != "" && cmd.deleteAPIKey {
		satelliteNodeURL, err := storj.ParseNodeURL(authRecord.SatelliteAddress)
		if err != nil {
			return errs.New("parse node url: %w", err)
		}

		client, ok := cmd.satAdminClients[satelliteNodeURL.Address]
		if !ok {
			return errs.New("could not find satellite admin address for %q", satelliteNodeURL.Address)
		}

		if err := client.DeleteAPIKey(ctx, authRecord.APIKey); err != nil {
			return errs.New("delete api key: %w", satAPIKeyError(err))
		}
	}

	if err := cmd.authClient.Delete(ctx, cmd.key); err != nil {
		return errs.New("delete: %w", err)
	}

	return nil
}

func printRecord(r record) {
	if r.AuthRecord != (authadminclient.Record{}) {
		if r.AuthRecord.CreatedAtUnix != 0 {
			printFixed("Created:", time.Unix(r.AuthRecord.CreatedAtUnix, 0).UTC().Format(time.RFC3339))
		}
		printFixed("Public:", strconv.FormatBool(r.AuthRecord.Public))
		if r.AuthRecord.ExpiresAtUnix != 0 {
			printFixed("Expires:", time.Unix(r.AuthRecord.ExpiresAtUnix, 0).UTC().Format(time.RFC3339))
		}
		if r.AuthRecord.InvalidatedAtUnix != 0 {
			printFixed("Invalidated:", time.Unix(r.AuthRecord.InvalidatedAtUnix, 0).UTC().Format(time.RFC3339))
		}
		if r.AuthRecord.InvalidationReason != "" {
			printFixed("Invalidation reason:", r.AuthRecord.InvalidationReason)
		}
		if r.AuthRecord.SatelliteAddress != "" {
			printFixed("Satellite address:", r.AuthRecord.SatelliteAddress)
		}
		if r.AuthRecord.MacaroonHeadHex != "" {
			printFixed("Macaroon head:", r.AuthRecord.MacaroonHeadHex)
		}
		if r.AuthRecord.APIKey != "" {
			printFixed("API key:", r.AuthRecord.APIKey)
		}
		if r.AuthRecord.DecryptedAccessGrant != "" {
			printFixed("Access grant:", r.AuthRecord.DecryptedAccessGrant)
		}
	}
	if r.SatRecord != (satelliteadminclient.APIKeyResponse{}) {
		printFixed("Project ID:", r.SatRecord.Project.ID.String())
		printFixed("Owner ID:", r.SatRecord.Owner.ID.String())
		printFixed("Owner name:", r.SatRecord.Owner.FullName)
		printFixed("Owner email:", r.SatRecord.Owner.Email)
		printFixed("Paid tier:", strconv.FormatBool(r.SatRecord.Owner.PaidTier))
	}
}

func printFixed(name, value string) {
	fmt.Printf("%-20s %s\n", name, value)
}
