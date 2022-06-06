// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"context"
	"errors"
	"time"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/gateway-mt/pkg/auth/sqlauth"
	"storj.io/private/dbutil"
	"storj.io/private/dbutil/pgutil"
	"storj.io/private/process"
	"storj.io/private/tagsql"
)

var mon = monkit.Package()

var (
	rootCmd   = &cobra.Command{Use: "authservice-unused-records"}
	deleteCmd = &cobra.Command{Use: "delete", RunE: deleteCommand}
	config    Config
)

// Config holds flags' values.
type Config struct {
	AuthServiceDB      string
	AsOfSystemInterval time.Duration
	MacaroonHead       []byte
	SelectSize         int
	DeleteSize         int
	DryRun             bool
}

func (config *Config) bindFlags(set *pflag.FlagSet) {
	set.StringVar(&config.AuthServiceDB, "authservicedb", "", "DSN for the auth service's database")
	set.DurationVar(&config.AsOfSystemInterval, "as-of-system-interval", -5*time.Second, "the interval specified in AS OF SYSTEM")
	set.BytesHexVar(&config.MacaroonHead, "macaroon-head", []byte{}, "macaroon head")
	set.IntVar(&config.SelectSize, "select-size", 10000, "batch size of records selected for deletion at a time")
	set.IntVar(&config.DeleteSize, "delete-size", 1000, "batch size of records to delete from selected records at a time")
	set.BoolVar(&config.DryRun, "dry-run", false, "specifying this flag will only calculate the number of records to delete and will not delete any")
}

// VerifyFlags verifies whether flags have correct values and reports any error
// encountered.
func (config *Config) VerifyFlags() error {
	var errlist errs.Group

	if config.AuthServiceDB == "" {
		errlist.Add(errors.New("authservicedb must be set"))
	}
	if config.AsOfSystemInterval > -time.Microsecond {
		errlist.Add(errors.New("as-of-system-interval cannot be greater than -1 μs"))
	}
	if len(config.MacaroonHead) == 0 {
		errlist.Add(errors.New("macaroon-head must be set"))
	}
	if config.SelectSize < 1 || config.SelectSize > 20000 {
		errlist.Add(errors.New("select-size must be 0 < select-size < 20000"))
	}
	if config.DeleteSize < 1 || config.DeleteSize > 5000 {
		errlist.Add(errors.New("delete-size must be 0 < delete-size < 5000"))
	}

	return errlist.Err()
}

func init() {
	rootCmd.AddCommand(deleteCmd)

	config.bindFlags(deleteCmd.Flags())
}

func main() {
	process.Exec(rootCmd)
}

func deleteCommand(cmd *cobra.Command, _ []string) error {
	if err := config.VerifyFlags(); err != nil {
		return err
	}

	ctx, cancel := process.Ctx(cmd)
	defer cancel()

	log := zap.L()

	opts := sqlauth.Options{
		ApplicationName: "authservice-unused-records",
	}

	k, err := sqlauth.Open(ctx, log, config.AuthServiceDB, opts)
	if err != nil {
		return err
	}

	defer func() { err = errs.Combine(err, k.Close()) }()

	db, impl := k.TagSQL(), dbutil.ImplementationForScheme(k.Schema())

	wouldDelete, count, rounds, err := Delete(ctx, log, db, impl, config)

	if config.DryRun {
		log.Sugar().Infof("Would delete %d records", wouldDelete)
	} else {
		log.Info("Stats", zap.Int64("count", count), zap.Int64("rounds", rounds))
	}

	return err
}

// Delete performs deletion and returns the number of records it would delete
// (for the `--dry-run` flag), number of deleted records, number of rounds it
// took to delete these records, and any error encountered.
func Delete(ctx context.Context, log *zap.Logger, db tagsql.DB, impl dbutil.Implementation, cfg Config) (wouldDelete int, count, rounds int64, err error) {
	defer mon.Task()(&ctx)(&err)

	var marker [32]byte

	for {
		pkvals, err := selectUnused(ctx, db, impl, cfg.AsOfSystemInterval, cfg.MacaroonHead, marker[:], cfg.SelectSize)
		if err != nil {
			return wouldDelete, count, rounds, err
		}

		wouldDelete += len(pkvals)

		if len(pkvals) == 0 {
			return wouldDelete, count, rounds, nil
		}

		copy(marker[:], pkvals[len(pkvals)-1])

		for !cfg.DryRun && len(pkvals) > 0 {
			var batch [][]byte

			batch, pkvals = sqlauth.BatchValues(pkvals, cfg.DeleteSize)

			res, err := db.ExecContext(
				ctx,
				`
				DELETE
				FROM records
				WHERE encryption_key_hash = ANY ($1::BYTEA[])
				`,
				pgutil.ByteaArray(batch),
			)
			if err != nil {
				return wouldDelete, count, rounds, err
			}

			c, err := res.RowsAffected()
			if err == nil { // Not every database or database driver may support RowsAffected.
				count += c
			}

			rounds++
		}

		if !cfg.DryRun && impl == dbutil.Cockroach {
			time.Sleep(-cfg.AsOfSystemInterval)
		}
	}
}

func selectUnused(ctx context.Context, db tagsql.DB, impl dbutil.Implementation, asOfSystemInterval time.Duration, macaroonHead, marker []byte, selectSize int) (pkvals [][]byte, err error) {
	defer mon.Task()(&ctx)(&err)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}

	// We don't commit the transaction and only roll it back, in any case, to
	// release any read locks early.
	defer func() { err = errs.Combine(err, tx.Rollback()) }()

	if impl == dbutil.Cockroach {
		if _, err = tx.ExecContext(
			ctx,
			"SET TRANSACTION"+impl.AsOfSystemInterval(asOfSystemInterval),
		); err != nil {
			return nil, err
		}
	}

	rows, err := tx.QueryContext(
		ctx,
		`
		SELECT encryption_key_hash
		FROM records
		WHERE expires_at IS NULL
		  AND macaroon_head = $1::BYTEA
		  AND encryption_key_hash > $2::BYTEA
		ORDER BY encryption_key_hash
		LIMIT $3
		`,
		macaroonHead,
		marker,
		selectSize,
	)
	if err != nil {
		return nil, err
	}

	defer func() { err = errs.Combine(err, rows.Close()) }()

	for rows.Next() {
		var pkval []byte

		if err = rows.Scan(&pkval); err != nil {
			return nil, err
		}

		pkvals = append(pkvals, pkval)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return pkvals, nil
}
