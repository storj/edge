// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package spannerauth

import (
	"context"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"google.golang.org/api/option"
	"google.golang.org/api/option/internaloption"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"

	"storj.io/edge/pkg/auth/authdb"
)

// defaultExactStaleness is the default value for how stale reads from Cloud
// Spanner should be. As described in Cloud Spanner Replication
// (https://cloud.google.com/spanner/docs/replication#read-only), 15 seconds is
// a reasonable staleness value to use for good performance.
const defaultExactStaleness = 15 * time.Second // [0, time.Hour)

var (
	_ authdb.Storage      = (*CloudDatabase)(nil)
	_ authdb.StorageAdmin = (*CloudDatabase)(nil)

	// Error is a class of spannerauth errors.
	Error = errs.Class("spannerauth")
	mon   = monkit.Package()
)

// Config is config to configure the Cloud Spanner database.
type Config struct {
	DatabaseName        string `user:"true" help:"name of Cloud Spanner database in the form projects/PROJECT_ID/instances/INSTANCE_ID/databases/DATABASE_ID"`
	CredentialsFilename string `user:"true" help:"credentials file with access to Cloud Spanner database"`

	// Address is used for Cloud Spanner Emulator in tests.
	Address string `internal:"true"`
}

// CloudDatabase represents a remote Cloud Spanner database that implements the
// Storage interface.
type CloudDatabase struct {
	logger *zap.Logger
	client *spanner.Client

	table string
}

// Open returns initialized CloudDatabase connected to Cloud Spanner. If address
// is specified in config, it configures options for Cloud Spanner Emulator.
func Open(ctx context.Context, logger *zap.Logger, config Config) (*CloudDatabase, error) {
	opts := []option.ClientOption{option.WithCredentialsFile(config.CredentialsFilename)}
	if config.Address != "" {
		opts = append(opts, EmulatorOpts(config.Address)...)
	}
	c, err := spanner.NewClientWithConfig(ctx, config.DatabaseName, spanner.ClientConfig{
		Logger:      zap.NewStdLog(logger),
		Compression: "gzip",
	}, opts...)
	return &CloudDatabase{
		logger: logger,
		client: c,
		table:  "records",
	}, Error.Wrap(err)
}

// EmulatorOpts returns ClientOptions for Cloud Spanner Emulator.
func EmulatorOpts(addr string) []option.ClientOption {
	return []option.ClientOption{
		option.WithEndpoint(addr),
		option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
		option.WithoutAuthentication(),
		internaloption.SkipDialSettingsValidation(),
	}
}

// Put stores the record in the remote Cloud Spanner database.
// It is an error if the key already exists.
func (d *CloudDatabase) Put(ctx context.Context, keyHash authdb.KeyHash, record *authdb.Record) (err error) {
	return d.PutWithCreatedAt(ctx, keyHash, record, time.Time{})
}

// PutWithCreatedAt is a temporary addition to ensure we migrate the created date
// when used with spannerauthmigration, because authdb.Record has no way of setting
// this directly. This should be removed once the migration has completed.
func (d *CloudDatabase) PutWithCreatedAt(ctx context.Context, keyHash authdb.KeyHash, record *authdb.Record, createdAt time.Time) (err error) {
	defer mon.Task()(&ctx)(&err)

	in := map[string]interface{}{
		"encryption_key_hash":    keyHash.Bytes(),
		"public":                 record.Public,
		"satellite_address":      record.SatelliteAddress,
		"macaroon_head":          record.MacaroonHead,
		"encrypted_secret_key":   record.EncryptedSecretKey,
		"encrypted_access_grant": record.EncryptedAccessGrant,
		// "invalidation_reason"
		// "invalidated_at"
	}

	// if a zero value createdAt is passed, we don't set anything so the
	// the database will default to setting this to the current timestamp.
	if !createdAt.IsZero() {
		in["created_at"] = createdAt
	}

	// we do not set any expiry unless it's non-zero. If an empty time.Time was
	// passed, then the value should be null in the database to ensure row
	// deletion policy doesn't inadvertently delete non-expiring records.
	if record.ExpiresAt != nil && !record.ExpiresAt.IsZero() {
		in["expires_at"] = record.ExpiresAt
	}

	ms := []*spanner.Mutation{
		spanner.InsertMap("records", in),
	}
	t, err := d.client.Apply(ctx, ms)
	if err != nil {
		return Error.Wrap(err)
	}
	d.logger.Debug("applied", zap.String("encryption_key_hash", keyHash.ToHex()), zap.Time("commit timestamp", t))
	return nil
}

// Get retrieves the record from the remote Cloud Spanner database.
// It returns (nil, nil) if the key does not exist.
// If the record is invalid, the error contains why.
func (d *CloudDatabase) Get(ctx context.Context, keyHash authdb.KeyHash) (_ *authdb.Record, err error) {
	full, err := d.GetFullRecord(ctx, keyHash)
	if err != nil {
		return nil, err
	}
	if full == nil {
		return nil, nil
	}
	if full.IsInvalid() {
		return nil, Error.Wrap(authdb.Invalid.New("%s", full.InvalidationReason))
	}
	return &full.Record, nil
}

// GetFullRecord retrieves the record from the remote Cloud Spanner database.
// It returns (nil, nil) if the key does not exist.
func (d *CloudDatabase) GetFullRecord(ctx context.Context, keyHash authdb.KeyHash) (_ *authdb.FullRecord, err error) {
	defer mon.Task()(&ctx)(&err)

	key := spanner.Key{keyHash.Bytes()}
	col := []string{
		"public",
		"satellite_address",
		"macaroon_head",
		"expires_at",
		"encrypted_secret_key",
		"encrypted_access_grant",
		"invalidation_reason",
		"invalidated_at",
	}

	boundedTx := d.client.Single().WithTimestampBound(spanner.ExactStaleness(defaultExactStaleness))
	defer boundedTx.Close()

	row, err := boundedTx.ReadRow(ctx, d.table, key, col)
	if err != nil {
		if !isRecordNotFound(err) {
			return nil, Error.Wrap(err)
		}
		// The bounded read didn't return a record, but it might have just been
		// inserted, so we will perform a strong read as a slow path.
		tx := d.client.Single()
		defer tx.Close()
		row, err = tx.ReadRow(ctx, d.table, key, col)
		if err != nil {
			if !isRecordNotFound(err) {
				return nil, Error.Wrap(err)
			}
			return nil, nil
		}
	}

	record := new(authdb.FullRecord)
	if err := row.ColumnByName("public", &record.Public); err != nil {
		return nil, Error.Wrap(err)
	}
	if err := row.ColumnByName("satellite_address", &record.SatelliteAddress); err != nil {
		return nil, Error.Wrap(err)
	}
	if err := row.ColumnByName("macaroon_head", &record.MacaroonHead); err != nil {
		return nil, Error.Wrap(err)
	}
	if err := row.ColumnByName("expires_at", &record.ExpiresAt); err != nil {
		return nil, Error.Wrap(err)
	}
	if err := row.ColumnByName("encrypted_secret_key", &record.EncryptedSecretKey); err != nil {
		return nil, Error.Wrap(err)
	}
	if err := row.ColumnByName("encrypted_access_grant", &record.EncryptedAccessGrant); err != nil {
		return nil, Error.Wrap(err)
	}

	var invalidationReason spanner.NullString
	if err := row.ColumnByName("invalidation_reason", &invalidationReason); err != nil {
		return nil, Error.Wrap(err)
	}
	record.InvalidationReason = invalidationReason.StringVal

	var invalidatedAt spanner.NullTime
	if err := row.ColumnByName("invalidated_at", &invalidatedAt); err != nil {
		return nil, Error.Wrap(err)
	}
	record.InvalidatedAt = invalidatedAt.Time

	// From https://cloud.google.com/spanner/docs/ttl:
	//
	// TTL garbage collection deletes eligible rows continuously and in the
	// background. Because this is an asynchronous background process, there is
	// a delay between eligibility and deletion. The table might contain rows
	// that is eligible for TTL deletion but for which TTL has not completed,
	// yet. Typically, the delay is less than 72 hours.
	if record.ExpiresAt != nil && record.ExpiresAt.Before(time.Now()) {
		// So if the record is expired, we don't want to return it anymore, and
		// it will be deleted at a later time.
		return nil, nil
	}

	return record, nil
}

// HealthCheck ensures there's connectivity to the remote Cloud Spanner database
// and returns an error otherwise.
func (d *CloudDatabase) HealthCheck(ctx context.Context) error {
	// TODO(amwolff): figure out how to implement this (do we need to?)
	return nil
}

// Run is a no-op.
func (d *CloudDatabase) Run(ctx context.Context) error {
	return nil
}

// Close closes the remote Cloud Spanner database.
func (d *CloudDatabase) Close() error {
	d.client.Close()
	return nil
}

// Invalidate invalidates the record.
func (d *CloudDatabase) Invalidate(ctx context.Context, keyHash authdb.KeyHash, reason string) (err error) {
	defer mon.Task()(&ctx)(&err)

	t, err := d.client.Apply(ctx, []*spanner.Mutation{spanner.UpdateMap(d.table, map[string]interface{}{
		"encryption_key_hash": keyHash.Bytes(),
		"invalidation_reason": reason,
		"invalidated_at":      time.Now(),
	})})
	if err != nil {
		return Error.Wrap(err)
	}

	d.logger.Debug("invalidated", zap.String("encryption_key_hash", keyHash.ToHex()), zap.Time("commit timestamp", t))

	return nil
}

// Unpublish unpublishes the record.
func (d *CloudDatabase) Unpublish(ctx context.Context, keyHash authdb.KeyHash) (err error) {
	defer mon.Task()(&ctx)(&err)

	t, err := d.client.Apply(ctx, []*spanner.Mutation{spanner.UpdateMap(d.table, map[string]interface{}{
		"encryption_key_hash": keyHash.Bytes(),
		"public":              false,
	})})
	if err != nil {
		return Error.Wrap(err)
	}

	d.logger.Debug("unpublished", zap.String("encryption_key_hash", keyHash.ToHex()), zap.Time("commit timestamp", t))

	return nil
}

// Delete deletes the record.
func (d *CloudDatabase) Delete(ctx context.Context, keyHash authdb.KeyHash) (err error) {
	defer mon.Task()(&ctx)(&err)

	t, err := d.client.Apply(ctx, []*spanner.Mutation{spanner.Delete(d.table, spanner.Key{keyHash.Bytes()})})
	if err != nil {
		return Error.Wrap(err)
	}

	d.logger.Debug("deleted", zap.String("encryption_key_hash", keyHash.ToHex()), zap.Time("commit timestamp", t))

	return nil
}

func isRecordNotFound(err error) bool {
	return spanner.ErrCode(err) == codes.NotFound
}
