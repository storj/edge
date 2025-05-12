// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package server_test

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/tags"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"storj.io/common/cfgstruct"
	"storj.io/common/errs2"
	"storj.io/common/fpath"
	"storj.io/common/grant"
	"storj.io/common/macaroon"
	"storj.io/common/memory"
	"storj.io/common/storj"
	"storj.io/common/sync2"
	"storj.io/common/testcontext"
	"storj.io/common/testrand"
	"storj.io/edge/internal/minioclient"
	"storj.io/edge/internal/register"
	"storj.io/edge/pkg/auth"
	"storj.io/edge/pkg/auth/spannerauth"
	"storj.io/edge/pkg/auth/spannerauth/spannerauthtest"
	"storj.io/edge/pkg/authclient"
	"storj.io/edge/pkg/server"
	"storj.io/edge/pkg/server/middleware"
	"storj.io/edge/pkg/serveraccesslogs"
	"storj.io/edge/pkg/trustedip"
	"storj.io/minio/pkg/bucket/versioning"
	"storj.io/storj/private/testplanet"
	"storj.io/storj/satellite"
	"storj.io/storj/satellite/buckets"
	"storj.io/storj/shared/dbutil"
	"storj.io/uplink"
)

const (
	lockModeCompliance = s3.ObjectLockModeCompliance
	lockModeGovernance = s3.ObjectLockModeGovernance
	legalHoldOn        = s3.ObjectLockLegalHoldStatusOn
	legalHoldOff       = s3.ObjectLockLegalHoldStatusOff
)

func TestObjectLockRestrictedPermissions(t *testing.T) {
	t.Parallel()

	runTest(t, testplanet.Config{
		SatelliteCount:   1,
		StorageNodeCount: 0,
		UplinkCount:      1,
		Reconfigure: testplanet.Reconfigure{
			Satellite: func(log *zap.Logger, index int, config *satellite.Config) {
				config.Metainfo.ObjectLockEnabled = true
				config.Metainfo.UseBucketLevelObjectVersioning = true
			},
			Uplink: func(log *zap.Logger, index int, config *testplanet.UplinkConfig) {
				config.APIKeyVersion = macaroon.APIKeyVersionObjectLock
			},
		},
	}, nil, func(ctx *testcontext.Context, planet *testplanet.Planet, gateway *server.Peer, auth *auth.Peer, creds register.Credentials) {
		satellite := planet.Satellites[0]
		projectID := planet.Uplinks[0].Projects[0].ID
		ownerID := planet.Uplinks[0].Projects[0].Owner.ID
		apiKey := planet.Uplinks[0].APIKey[planet.Satellites[0].ID()]

		encAccess := grant.NewEncryptionAccessWithDefaultKey(&storj.Key{})
		encAccess.SetDefaultPathCipher(storj.EncNull)

		allowedCreds := registerAccess(ctx, t, encAccess, apiKey, satellite.URL(), auth.Address())
		allowedClient := createS3Client(t, gateway.Address(), allowedCreds.AccessKeyID, allowedCreds.SecretKey)

		bucket := testrand.BucketName()
		require.NoError(t, createBucket(ctx, allowedClient, bucket, true, true))

		objKey1 := "testobject1"

		retainUntil := time.Now().Add(10 * time.Minute)

		t.Run("api key version disallows object lock", func(t *testing.T) {
			userCtx, err := satellite.UserContext(ctx, ownerID)
			require.NoError(t, err)

			_, apiKey, err := satellite.API.Console.Service.CreateAPIKey(userCtx, projectID, "restricted", macaroon.APIKeyVersionMin)
			require.NoError(t, err)

			creds := registerAccess(ctx, t, encAccess, apiKey, satellite.URL(), auth.Address())
			client := createS3Client(t, gateway.Address(), creds.AccessKeyID, creds.SecretKey)

			requireS3Error(t, createBucket(ctx, client, testrand.BucketName(), true, true), http.StatusForbidden, "AccessDenied")
		})

		restrictedClient := func(t *testing.T, caveat macaroon.Caveat) *s3.S3 {
			restrictedApiKey, err := apiKey.Restrict(caveat)
			require.NoError(t, err)

			creds := registerAccess(ctx, t, encAccess, restrictedApiKey, satellite.URL(), auth.Address())
			return createS3Client(t, gateway.Address(), creds.AccessKeyID, creds.SecretKey)
		}

		t.Run("disallow put retention", func(t *testing.T) {
			client := restrictedClient(t, macaroon.Caveat{
				DisallowPutRetention: true,
			})

			_, err := putObjectWithRetention(ctx, client, bucket, objKey1, lockModeCompliance, retainUntil)
			requireS3Error(t, err, http.StatusForbidden, "AccessDenied")

			putResp, err := putObjectWithRetention(ctx, allowedClient, bucket, objKey1, lockModeCompliance, retainUntil)
			require.NoError(t, err)

			_, err = putObjectRetention(ctx, client, bucket, objKey1, lockModeCompliance, retainUntil, *putResp.VersionId)
			requireS3Error(t, err, http.StatusForbidden, "AccessDenied")
		})

		t.Run("allow put retention implicitly allows get retention", func(t *testing.T) {
			client := restrictedClient(t, macaroon.Caveat{
				DisallowGetRetention: true,
			})

			putResp, err := putObjectWithRetention(ctx, client, bucket, objKey1, lockModeCompliance, retainUntil)
			require.NoError(t, err)

			retResp, err := getObjectRetention(ctx, client, bucket, objKey1, *putResp.VersionId)
			require.NoError(t, err)
			require.Equal(t, lockModeCompliance, *retResp.Retention.Mode)
			require.WithinDuration(t, retainUntil, *retResp.Retention.RetainUntilDate, time.Minute)
		})

		t.Run("disallow put legal hold", func(t *testing.T) {
			client := restrictedClient(t, macaroon.Caveat{
				DisallowPutLegalHold: true,
			})

			putResp, err := putObject(ctx, client, bucket, objKey1, nil)
			require.NoError(t, err)

			_, err = putObjectLegalHold(ctx, client, bucket, objKey1, legalHoldOn, *putResp.VersionId)
			requireS3Error(t, err, http.StatusForbidden, "AccessDenied")

			_, err = putObjectWithLegalHold(ctx, client, bucket, objKey1, legalHoldOn)
			requireS3Error(t, err, http.StatusForbidden, "AccessDenied")

			lhResp, err := getObjectLegalHold(ctx, client, bucket, objKey1, *putResp.VersionId)
			require.NoError(t, err)
			require.Equal(t, legalHoldOff, *lhResp.LegalHold.Status)
		})

		t.Run("disallow get legal hold", func(t *testing.T) {
			client := restrictedClient(t, macaroon.Caveat{
				DisallowGetLegalHold: true,
			})

			putResp, err := putObject(ctx, client, bucket, objKey1, nil)
			require.NoError(t, err)

			_, err = putObjectLegalHold(ctx, client, bucket, objKey1, legalHoldOn, *putResp.VersionId)
			require.NoError(t, err)

			_, err = putObjectWithLegalHold(ctx, client, bucket, objKey1, legalHoldOn)
			require.NoError(t, err)

			_, err = getObjectLegalHold(ctx, client, bucket, objKey1, *putResp.VersionId)
			requireS3Error(t, err, http.StatusForbidden, "AccessDenied")
		})

		t.Run("disallow governance bypass", func(t *testing.T) {
			client := restrictedClient(t, macaroon.Caveat{
				DisallowBypassGovernanceRetention: true,
			})

			putResp, err := putObjectWithRetention(ctx, client, bucket, objKey1, lockModeGovernance, retainUntil)
			require.NoError(t, err)

			requireS3Error(t, deleteObjectBypassGovernance(ctx, client, bucket, objKey1, *putResp.VersionId), http.StatusForbidden, "AccessDenied")
		})

		t.Run("disallow put object lock configuration", func(t *testing.T) {
			client := restrictedClient(t, macaroon.Caveat{
				DisallowPutBucketObjectLockConfiguration: true,
			})

			retDays := int64(5)
			retMode := s3.ObjectLockRetentionModeCompliance

			_, err := putObjectLockConfiguration(ctx, client, bucket, "Enabled", &s3.ObjectLockRule{
				DefaultRetention: &s3.DefaultRetention{
					Days: &retDays,
					Mode: &retMode,
				},
			})
			requireS3Error(t, err, http.StatusForbidden, "AccessDenied")
		})

		t.Run("disallow get object lock configuration", func(t *testing.T) {
			client := restrictedClient(t, macaroon.Caveat{
				DisallowGetBucketObjectLockConfiguration: true,
			})

			retDays := int64(5)
			retMode := s3.ObjectLockRetentionModeCompliance

			_, err := putObjectLockConfiguration(ctx, client, bucket, "Enabled", &s3.ObjectLockRule{
				DefaultRetention: &s3.DefaultRetention{
					Days: &retDays,
					Mode: &retMode,
				},
			})
			require.NoError(t, err)

			_, err = getObjectLockConfiguration(ctx, client, bucket)
			requireS3Error(t, err, http.StatusForbidden, "AccessDenied")
		})
	})
}

func TestObjectLock(t *testing.T) {
	t.Parallel()

	runTest(t, testplanet.Config{
		SatelliteCount:   1,
		StorageNodeCount: 0,
		UplinkCount:      1,
		Reconfigure: testplanet.Reconfigure{
			Satellite: func(log *zap.Logger, index int, config *satellite.Config) {
				config.Metainfo.ObjectLockEnabled = true
				config.Metainfo.UseBucketLevelObjectVersioning = true
				config.Metainfo.ProjectLimits.MaxBuckets = 100
			},
			Uplink: func(log *zap.Logger, index int, config *testplanet.UplinkConfig) {
				config.APIKeyVersion = macaroon.APIKeyVersionObjectLock
			},
		},
	}, nil, func(ctx *testcontext.Context, planet *testplanet.Planet, gateway *server.Peer, auth *auth.Peer, creds register.Credentials) {
		client := createS3Client(t, gateway.Address(), creds.AccessKeyID, creds.SecretKey)

		bucket := testrand.BucketName()
		require.NoError(t, createBucket(ctx, client, bucket, true, true))

		objKey1, objKey2, objKey3 := "testobject1", "testobject2", "testobject3"

		retainUntil := time.Now().Add(10 * time.Minute)

		runRetentionModeTest := func(name string, f func(t *testing.T, mode string)) {
			t.Run(name+" (compliance mode)", func(t *testing.T) {
				f(t, lockModeCompliance)
			})
			t.Run(name+" (governance mode)", func(t *testing.T) {
				f(t, lockModeGovernance)
			})
		}

		t.Run("enable and disable object lock on bucket", func(t *testing.T) {
			noLockBucket := testrand.BucketName()
			require.NoError(t, createBucket(ctx, client, noLockBucket, true, false))

			_, err := getObjectLockConfiguration(ctx, client, noLockBucket)
			requireS3Error(t, err, http.StatusNotFound, "ObjectLockConfigurationNotFoundError")

			_, err = putObjectLockConfiguration(ctx, client, noLockBucket, "Disabled", nil)
			requireS3Error(t, err, http.StatusBadRequest, "MalformedXML")

			lockBucket := testrand.BucketName()
			require.NoError(t, createBucket(ctx, client, lockBucket, true, true))

			retDays := int64(5)
			retMode := s3.ObjectLockRetentionModeCompliance

			_, err = putObjectLockConfiguration(ctx, client, lockBucket, "Enabled", &s3.ObjectLockRule{
				DefaultRetention: &s3.DefaultRetention{
					Days: &retDays,
					Mode: &retMode,
				},
			})
			require.NoError(t, err)

			resp, err := getObjectLockConfiguration(ctx, client, lockBucket)
			require.NoError(t, err)
			require.Equal(t, "Enabled", *resp.ObjectLockConfiguration.ObjectLockEnabled)
			require.Equal(t, retMode, *resp.ObjectLockConfiguration.Rule.DefaultRetention.Mode)
			require.Equal(t, retDays, *resp.ObjectLockConfiguration.Rule.DefaultRetention.Days)
			require.Nil(t, resp.ObjectLockConfiguration.Rule.DefaultRetention.Years)

			retMode = s3.ObjectLockRetentionModeGovernance
			retYears := int64(1)

			_, err = putObjectLockConfiguration(ctx, client, lockBucket, "Enabled", &s3.ObjectLockRule{
				DefaultRetention: &s3.DefaultRetention{
					Years: &retYears,
					Mode:  &retMode,
				},
			})
			require.NoError(t, err)

			resp, err = getObjectLockConfiguration(ctx, client, lockBucket)
			require.NoError(t, err)
			require.Equal(t, "Enabled", *resp.ObjectLockConfiguration.ObjectLockEnabled)
			require.Equal(t, retMode, *resp.ObjectLockConfiguration.Rule.DefaultRetention.Mode)
			require.Equal(t, retYears, *resp.ObjectLockConfiguration.Rule.DefaultRetention.Years)
			require.Nil(t, resp.ObjectLockConfiguration.Rule.DefaultRetention.Days)

			putObjResp, err := putObject(ctx, client, lockBucket, objKey1, nil)
			require.NoError(t, err)

			objInfo, err := getObject(ctx, client, lockBucket, objKey1, *putObjResp.VersionId)
			require.NoError(t, err)

			require.Equal(t, retMode, *objInfo.ObjectLockMode)
			require.WithinDuration(t, time.Now().AddDate(int(retYears), 0, 0), *objInfo.ObjectLockRetainUntilDate, time.Minute)

			requireS3Error(t, deleteObject(ctx, client, lockBucket, objKey1, *putObjResp.VersionId), http.StatusForbidden, "AccessDenied")
		})

		t.Run("put object with default retention encompassing leap day", func(t *testing.T) {
			test := func(t *testing.T, defaultRetentionYears, defaultRetentionDays int, expectedRetainUntil time.Time) {
				bucketName := testrand.BucketName()
				require.NoError(t, createBucket(ctx, client, bucketName, true, true))

				defaultRetention := s3.DefaultRetention{
					Mode: aws.String(s3.ObjectLockModeCompliance),
				}
				if defaultRetentionYears != 0 {
					defaultRetention.Years = aws.Int64(int64(defaultRetentionYears))
				} else if defaultRetentionDays != 0 {
					defaultRetention.Days = aws.Int64(int64(defaultRetentionDays))
				}

				_, err := client.PutObjectLockConfigurationWithContext(ctx, &s3.PutObjectLockConfigurationInput{
					Bucket: &bucketName,
					ObjectLockConfiguration: &s3.ObjectLockConfiguration{
						ObjectLockEnabled: aws.String("Enabled"),
						Rule: &s3.ObjectLockRule{
							DefaultRetention: &defaultRetention,
						},
					},
				})
				require.NoError(t, err)

				objectKey := "file.txt"

				_, err = putObject(ctx, client, bucketName, objectKey, nil)
				require.NoError(t, err)

				resp, err := getObjectRetention(ctx, client, bucketName, objectKey, "")
				require.NoError(t, err)

				require.WithinDuration(t, expectedRetainUntil, *resp.Retention.RetainUntilDate, time.Minute)
			}

			// Find the nearest date N years after the current date that lies after a leap day.
			now := time.Now()
			leapYear := now.Year()
			var leapDay time.Time
			for {
				if (leapYear%4 == 0 && leapYear%100 != 0) || (leapYear%400 == 0) {
					leapDay = time.Date(leapYear, time.February, 29, 0, 0, 0, 0, time.UTC)
					if leapDay.After(now) {
						break
					}
				}
				leapYear++
			}
			years := leapYear - now.Year()
			if now.AddDate(years, 0, 0).Before(leapDay) {
				years++
			}

			t.Run("Default retention as days", func(t *testing.T) {
				// Expect 1 day to always be considered a 24-hour period, with no adjustments
				// made to accommodate the leap day.
				test(t, 0, 365*years, time.Now().AddDate(0, 0, 365*years))
			})

			t.Run("Default retention as years", func(t *testing.T) {
				// Expect the retention period duration to take the leap day into account.
				test(t, years, 0, time.Now().AddDate(0, 0, 365*years+1))
			})
		})

		t.Run("put object lock config on unversioned bucket not allowed", func(t *testing.T) {
			bucket := testrand.BucketName()
			require.NoError(t, createBucket(ctx, client, bucket, false, false))

			retDays := int64(5)
			retMode := s3.ObjectLockRetentionModeCompliance

			_, err := putObjectLockConfiguration(ctx, client, bucket, "Enabled", &s3.ObjectLockRule{
				DefaultRetention: &s3.DefaultRetention{
					Days: &retDays,
					Mode: &retMode,
				},
			})
			requireS3Error(t, err, http.StatusConflict, "InvalidBucketState")
		})

		t.Run("put object with lock not allowed on unversioned bucket", func(t *testing.T) {
			noVersioningBucket := testrand.BucketName()
			require.NoError(t, createBucket(ctx, client, noVersioningBucket, false, false))

			_, err := putObjectWithRetention(ctx, client, noVersioningBucket, objKey1, lockModeCompliance, retainUntil)
			requireS3Error(t, err, http.StatusBadRequest, "InvalidRequest")
		})

		t.Run("put object with lock enables versioning implicitly", func(t *testing.T) {
			noVersioningBucket := testrand.BucketName()
			require.NoError(t, createBucket(ctx, client, noVersioningBucket, false, true))

			resp, err := putObjectWithRetention(ctx, client, bucket, objKey1, lockModeCompliance, retainUntil)
			require.NoError(t, err)
			require.NotEmpty(t, resp.VersionId)
		})

		t.Run("put object with lock not allowed when bucket lock disabled", func(t *testing.T) {
			noLockBucket := testrand.BucketName()
			require.NoError(t, createBucket(ctx, client, noLockBucket, true, false))

			_, err := putObjectWithRetention(ctx, client, noLockBucket, objKey1, lockModeCompliance, retainUntil)
			requireS3Error(t, err, http.StatusBadRequest, "InvalidRequest")
		})

		t.Run("suspending versioning is not allowed when object lock enabled on bucket", func(t *testing.T) {
			_, err := client.PutBucketVersioning(&s3.PutBucketVersioningInput{
				Bucket: aws.String(bucket),
				VersioningConfiguration: &s3.VersioningConfiguration{
					Status: aws.String(s3.BucketVersioningStatusSuspended),
				},
			})
			requireS3Error(t, err, http.StatusConflict, "InvalidBucketState")
		})

		t.Run("get and put object retention error handling", func(t *testing.T) {
			noLockBucket := testrand.BucketName()
			require.NoError(t, createBucket(ctx, client, noLockBucket, true, false))

			_, err := putObject(ctx, client, noLockBucket, objKey1, nil)
			require.NoError(t, err)

			_, err = getObjectRetention(ctx, client, noLockBucket, objKey1, "")
			requireS3Error(t, err, http.StatusBadRequest, "InvalidRequest")
			// Note: S3 returns 400 InvalidRequest for GetObjectRetention when the bucket has no lock configuration.
			// If the bucket does have lock configuration it instead returns 404 NoSuchObjectLockConfiguration.

			_, err = putObject(ctx, client, bucket, objKey1, nil)
			require.NoError(t, err)

			_, err = getObjectRetention(ctx, client, bucket, objKey1, "")
			requireS3Error(t, err, http.StatusNotFound, "NoSuchObjectLockConfiguration")

			_, err = putObjectRetention(ctx, client, "nonexistent", objKey1, lockModeCompliance, retainUntil, "")
			requireS3Error(t, err, http.StatusNotFound, "NoSuchBucket")

			_, err = getObjectRetention(ctx, client, "nonexistent", objKey1, "")
			requireS3Error(t, err, http.StatusNotFound, "NoSuchBucket")

			_, err = putObjectRetention(ctx, client, bucket, "nonexistent", lockModeCompliance, retainUntil, "")
			requireS3Error(t, err, http.StatusNotFound, "NoSuchKey")

			_, err = getObjectRetention(ctx, client, bucket, "nonexistent", "")
			requireS3Error(t, err, http.StatusNotFound, "NoSuchKey")

			_, err = putObjectRetention(ctx, client, bucket, objKey1, "invalidmode", retainUntil, "")
			requireS3Error(t, err, http.StatusBadRequest, "MalformedXML")

			_, err = putObjectWithRetention(ctx, client, bucket, objKey1, "invalidmode", retainUntil)
			requireS3Error(t, err, http.StatusBadRequest, "InvalidArgument")

			_, err = putObjectMultipartWithRetention(ctx, client, bucket, objKey1, "invalidmode", retainUntil)
			requireS3Error(t, err, http.StatusBadRequest, "InvalidArgument")
		})

		t.Run("legal hold", func(t *testing.T) {
			putResp, err := putObjectWithLegalHold(ctx, client, bucket, objKey1, legalHoldOn)
			require.NoError(t, err)

			requireS3Error(t, deleteObject(ctx, client, bucket, objKey1, *putResp.VersionId), http.StatusForbidden, "AccessDenied")

			mpResp, err := putObjectMultipartWithLegalHold(ctx, client, bucket, objKey2, legalHoldOn)
			require.NoError(t, err)

			requireS3Error(t, deleteObject(ctx, client, bucket, objKey2, *mpResp.VersionId), http.StatusForbidden, "AccessDenied")

			for _, key := range []string{objKey1, objKey2} {
				lhResp, err := getObjectLegalHold(ctx, client, bucket, key, "")
				require.NoError(t, err)
				require.Equal(t, legalHoldOn, *lhResp.LegalHold.Status)
			}

			putResp, err = putObject(ctx, client, bucket, objKey3, nil)
			require.NoError(t, err)

			_, err = putObjectLegalHold(ctx, client, bucket, objKey3, legalHoldOn, *putResp.VersionId)
			require.NoError(t, err)

			lhResp, err := getObjectLegalHold(ctx, client, bucket, objKey3, *putResp.VersionId)
			require.NoError(t, err)
			require.Equal(t, legalHoldOn, *lhResp.LegalHold.Status)

			getObjResp, err := getObject(ctx, client, bucket, objKey3, *putResp.VersionId)
			require.NoError(t, err)
			require.Equal(t, legalHoldOn, *getObjResp.ObjectLockLegalHoldStatus)

			requireS3Error(t, deleteObject(ctx, client, bucket, objKey3, *putResp.VersionId), http.StatusForbidden, "AccessDenied")

			_, err = putObjectLegalHold(ctx, client, bucket, objKey3, legalHoldOff, *putResp.VersionId)
			require.NoError(t, err)

			lhResp, err = getObjectLegalHold(ctx, client, bucket, objKey3, *putResp.VersionId)
			require.NoError(t, err)
			require.Equal(t, legalHoldOff, *lhResp.LegalHold.Status)

			require.NoError(t, deleteObject(ctx, client, bucket, objKey3, *putResp.VersionId))
		})

		t.Run("get and put legal hold error handling", func(t *testing.T) {
			noLockBucket := testrand.BucketName()
			require.NoError(t, createBucket(ctx, client, noLockBucket, true, false))

			_, err := putObject(ctx, client, noLockBucket, objKey1, nil)
			require.NoError(t, err)

			_, err = getObjectLegalHold(ctx, client, noLockBucket, objKey1, "")
			requireS3Error(t, err, http.StatusBadRequest, "InvalidRequest")

			_, err = putObjectLegalHold(ctx, client, "nonexistent", objKey1, legalHoldOn, "")
			requireS3Error(t, err, http.StatusNotFound, "NoSuchBucket")

			_, err = getObjectLegalHold(ctx, client, "nonexistent", objKey1, "")
			requireS3Error(t, err, http.StatusNotFound, "NoSuchBucket")

			_, err = putObjectLegalHold(ctx, client, bucket, "nonexistent", legalHoldOn, "")
			requireS3Error(t, err, http.StatusNotFound, "NoSuchKey")

			_, err = getObjectLegalHold(ctx, client, bucket, "nonexistent", "")
			requireS3Error(t, err, http.StatusNotFound, "NoSuchKey")

			_, err = putObjectLegalHold(ctx, client, bucket, objKey1, "invalidstatus", "")
			requireS3Error(t, err, http.StatusBadRequest, "MalformedXML")

			_, err = putObjectLegalHold(ctx, client, bucket, objKey1, "", "")
			requireS3Error(t, err, http.StatusBadRequest, "MalformedXML")

			_, err = putObjectWithLegalHold(ctx, client, bucket, objKey1, "invalidstatus")
			requireS3Error(t, err, http.StatusBadRequest, "InvalidArgument")

			_, err = putObjectMultipartWithLegalHold(ctx, client, bucket, objKey1, "invalidstatus")
			requireS3Error(t, err, http.StatusBadRequest, "InvalidArgument")
		})

		runRetentionModeTest("legal hold and retention", func(t *testing.T, mode string) {
			putResp, err := putObjectWithLegalHoldAndRetention(ctx, client, bucket, objKey1, legalHoldOn, mode, retainUntil)
			require.NoError(t, err)

			lhResp, err := getObjectLegalHold(ctx, client, bucket, objKey1, *putResp.VersionId)
			require.NoError(t, err)
			require.Equal(t, legalHoldOn, *lhResp.LegalHold.Status)

			retResp, err := getObjectRetention(ctx, client, bucket, objKey1, *putResp.VersionId)
			require.NoError(t, err)
			require.Equal(t, mode, *retResp.Retention.Mode)
			require.WithinDuration(t, retainUntil, *retResp.Retention.RetainUntilDate, time.Minute)

			requireS3Error(t, deleteObject(ctx, client, bucket, objKey1, *putResp.VersionId), http.StatusForbidden, "AccessDenied")

			if mode == lockModeGovernance {
				requireS3Error(t, deleteObjectBypassGovernance(ctx, client, bucket, objKey1, *putResp.VersionId), http.StatusForbidden, "AccessDenied")
			}

			_, err = putObjectLegalHold(ctx, client, bucket, objKey1, legalHoldOff, *putResp.VersionId)
			require.NoError(t, err)

			requireS3Error(t, deleteObject(ctx, client, bucket, objKey1, *putResp.VersionId), http.StatusForbidden, "AccessDenied")

			if mode == lockModeGovernance {
				require.NoError(t, deleteObjectBypassGovernance(ctx, client, bucket, objKey1, *putResp.VersionId))
			}
		})

		t.Run("changing retention mode", func(t *testing.T) {
			putResp, err := putObjectWithRetention(ctx, client, bucket, objKey1, lockModeGovernance, retainUntil)
			require.NoError(t, err)

			_, err = putObjectRetention(ctx, client, bucket, objKey1, lockModeCompliance, retainUntil, *putResp.VersionId)
			requireS3Error(t, err, http.StatusForbidden, "AccessDenied")

			putResp, err = putObjectWithRetention(ctx, client, bucket, objKey1, lockModeCompliance, retainUntil)
			require.NoError(t, err)

			_, err = putObjectRetention(ctx, client, bucket, objKey1, lockModeGovernance, retainUntil, *putResp.VersionId)
			requireS3Error(t, err, http.StatusForbidden, "AccessDenied")
		})

		runRetentionModeTest("changing retention period", func(t *testing.T, mode string) {
			putResp, err := putObjectWithRetention(ctx, client, bucket, objKey1, mode, retainUntil)
			require.NoError(t, err)

			extendedRetainUntil := retainUntil.Add(10 * time.Minute)

			_, err = putObjectRetention(ctx, client, bucket, objKey1, mode, extendedRetainUntil, *putResp.VersionId)
			require.NoError(t, err)

			objInfo, err := getObject(ctx, client, bucket, objKey1, "")
			require.NoError(t, err)
			require.WithinDuration(t, extendedRetainUntil, *objInfo.ObjectLockRetainUntilDate, time.Minute)

			_, err = putObjectRetention(ctx, client, bucket, objKey1, mode, extendedRetainUntil.Add(-time.Minute), *putResp.VersionId)
			requireS3Error(t, err, http.StatusForbidden, "AccessDenied")

			_, err = putObjectRetentionBypassGovernance(ctx, client, bucket, "nonexistent", mode, extendedRetainUntil.Add(-time.Hour), *putResp.VersionId)
			requireS3Error(t, err, http.StatusBadRequest, "InvalidArgument")

			if mode == lockModeGovernance {
				_, err = putObjectRetentionBypassGovernance(ctx, client, bucket, objKey1, mode, extendedRetainUntil.Add(-time.Minute), *putResp.VersionId)
				require.NoError(t, err)
			}
		})

		runRetentionModeTest("bypass governance remove retention", func(t *testing.T, mode string) {
			putResp, err := putObjectWithRetention(ctx, client, bucket, objKey1, mode, retainUntil)
			require.NoError(t, err)

			_, err = putObjectRetention(ctx, client, bucket, objKey1, "", time.Time{}, *putResp.VersionId)
			requireS3Error(t, err, http.StatusBadRequest, "InvalidArgument")

			_, err = putObjectRetentionBypassGovernance(ctx, client, bucket, objKey1, "", time.Time{}, *putResp.VersionId)
			if mode == lockModeGovernance {
				require.NoError(t, err)
				require.NoError(t, deleteObject(ctx, client, bucket, objKey1, *putResp.VersionId))
			} else {
				requireS3Error(t, err, http.StatusForbidden, "AccessDenied")
			}
		})

		runRetentionModeTest("object lock settings in object info", func(t *testing.T, mode string) {
			putResp, err := putObjectWithRetention(ctx, client, bucket, objKey1, mode, retainUntil)
			require.NoError(t, err)

			objInfo, err := getObject(ctx, client, bucket, objKey1, *putResp.VersionId)
			require.NoError(t, err)
			require.Equal(t, putResp.VersionId, objInfo.VersionId)
			require.Equal(t, mode, *objInfo.ObjectLockMode)
			require.WithinDuration(t, retainUntil, *objInfo.ObjectLockRetainUntilDate, time.Minute)

			_, err = getObjectRetention(ctx, client, bucket, "nonexistent", "")
			requireS3Error(t, err, http.StatusNotFound, "NoSuchKey")

			retResp, err := getObjectRetention(ctx, client, bucket, objKey1, *putResp.VersionId)
			require.NoError(t, err)
			require.Equal(t, mode, *retResp.Retention.Mode)
			require.WithinDuration(t, retainUntil, *retResp.Retention.RetainUntilDate, time.Minute)
		})

		runRetentionModeTest("delete locked object version", func(t *testing.T, mode string) {
			putResp, err := putObjectWithRetention(ctx, client, bucket, objKey1, mode, retainUntil)
			require.NoError(t, err)

			requireS3Error(t, deleteObject(ctx, client, bucket, objKey1, *putResp.VersionId), http.StatusForbidden, "AccessDenied")

			mpResp, err := putObjectMultipartWithRetention(ctx, client, bucket, objKey2, mode, retainUntil)
			require.NoError(t, err)

			requireS3Error(t, deleteObject(ctx, client, bucket, objKey2, *mpResp.VersionId), http.StatusForbidden, "AccessDenied")

			if mode == lockModeGovernance {
				require.NoError(t, deleteObjectBypassGovernance(ctx, client, bucket, objKey1, *putResp.VersionId))
				require.NoError(t, deleteObjectBypassGovernance(ctx, client, bucket, objKey2, *mpResp.VersionId))
			}
		})

		t.Run("invalid object state delete marker", func(t *testing.T) {
			_, err := putObjectWithRetention(ctx, client, bucket, objKey1, lockModeCompliance, retainUntil)
			require.NoError(t, err)

			require.NoError(t, deleteObject(ctx, client, bucket, objKey1, ""))

			_, err = getObjectRetention(ctx, client, bucket, objKey1, "")
			requireS3Error(t, err, http.StatusMethodNotAllowed, "MethodNotAllowed")

			_, err = putObjectRetention(ctx, client, bucket, objKey1, lockModeCompliance, retainUntil, "")
			requireS3Error(t, err, http.StatusMethodNotAllowed, "MethodNotAllowed")

			_, err = getObjectLegalHold(ctx, client, bucket, objKey1, "")
			requireS3Error(t, err, http.StatusMethodNotAllowed, "MethodNotAllowed")

			_, err = putObjectLegalHold(ctx, client, bucket, objKey1, legalHoldOn, "")
			requireS3Error(t, err, http.StatusMethodNotAllowed, "MethodNotAllowed")
		})

		runRetentionModeTest("copy object", func(t *testing.T, mode string) {
			noLockBucket := testrand.BucketName()
			require.NoError(t, createBucket(ctx, client, noLockBucket, true, false))

			putResp, err := putObjectWithRetention(ctx, client, bucket, objKey1, mode, retainUntil)
			require.NoError(t, err)

			_, err = copyObjectWithRetention(ctx, client, bucket, objKey1, *putResp.VersionId, noLockBucket, objKey2, mode, &retainUntil)
			requireS3Error(t, err, http.StatusBadRequest, "InvalidRequest")

			_, err = putObjectLegalHold(ctx, client, bucket, objKey1, legalHoldOn, *putResp.VersionId)
			require.NoError(t, err)

			copyResp, err := copyObject(ctx, client, bucket, objKey1, *putResp.VersionId, bucket, objKey2)
			require.NoError(t, err)

			_, err = getObjectRetention(ctx, client, bucket, objKey2, *copyResp.VersionId)
			requireS3Error(t, err, http.StatusNotFound, "NoSuchObjectLockConfiguration")

			objInfo, err := getObject(ctx, client, bucket, objKey2, "")
			require.NoError(t, err)
			require.Nil(t, objInfo.ObjectLockMode)
			require.Nil(t, objInfo.ObjectLockRetainUntilDate)
			require.Equal(t, legalHoldOff, *objInfo.ObjectLockLegalHoldStatus)

			require.NoError(t, deleteObject(ctx, client, bucket, objKey2, *copyResp.VersionId))

			copyResp, err = copyObjectWithRetention(ctx, client, bucket, objKey1, *putResp.VersionId, bucket, objKey3, mode, &retainUntil)
			require.NoError(t, err)

			getResp, err := getObject(ctx, client, bucket, objKey3, *copyResp.VersionId)
			require.NoError(t, err)
			require.Equal(t, mode, *getResp.ObjectLockMode)
			require.WithinDuration(t, retainUntil, *getResp.ObjectLockRetainUntilDate, time.Minute)

			requireS3Error(t, deleteObject(ctx, client, bucket, objKey3, *copyResp.VersionId), http.StatusForbidden, "AccessDenied")

			copyResp, err = copyObjectWithLegalHoldAndRetention(ctx, client, bucket, objKey1, *putResp.VersionId, bucket, objKey2, legalHoldOn, mode, &retainUntil)
			require.NoError(t, err)

			getResp, err = getObject(ctx, client, bucket, objKey2, *copyResp.VersionId)
			require.NoError(t, err)
			require.Equal(t, mode, *getResp.ObjectLockMode)
			require.WithinDuration(t, retainUntil, *getResp.ObjectLockRetainUntilDate, time.Minute)
			require.Equal(t, legalHoldOn, *getResp.ObjectLockLegalHoldStatus)
		})

		t.Run("copy object default retention", func(t *testing.T) {
			srcBucket, dstBucket := testrand.BucketName(), testrand.BucketName()
			require.NoError(t, createBucket(ctx, client, srcBucket, false, false))
			require.NoError(t, createBucket(ctx, client, dstBucket, true, true))

			defaultDays := int64(5)
			defaultMode := s3.ObjectLockRetentionModeCompliance

			_, err := putObjectLockConfiguration(ctx, client, dstBucket, "Enabled", &s3.ObjectLockRule{
				DefaultRetention: &s3.DefaultRetention{
					Days: &defaultDays,
					Mode: &defaultMode,
				},
			})
			require.NoError(t, err)

			_, err = putObject(ctx, client, srcBucket, objKey1, nil)
			require.NoError(t, err)

			copyResp, err := copyObject(ctx, client, srcBucket, objKey1, "", dstBucket, objKey1)
			require.NoError(t, err)

			objInfo, err := getObject(ctx, client, dstBucket, objKey1, *copyResp.VersionId)
			require.NoError(t, err)

			require.Equal(t, defaultMode, *objInfo.ObjectLockMode)
			require.WithinDuration(t, time.Now().AddDate(0, 0, int(defaultDays)), *objInfo.ObjectLockRetainUntilDate, time.Minute)

			copyResp, err = copyObjectWithRetention(ctx, client, srcBucket, objKey1, "", dstBucket, objKey2, s3.ObjectLockModeCompliance, &retainUntil)
			require.NoError(t, err)

			objInfo, err = getObject(ctx, client, dstBucket, objKey2, *copyResp.VersionId)
			require.NoError(t, err)

			require.Equal(t, s3.ObjectLockModeCompliance, *objInfo.ObjectLockMode)
			require.WithinDuration(t, retainUntil, *objInfo.ObjectLockRetainUntilDate, time.Minute)
		})

		runRetentionModeTest("mixed locked and unlocked versions", func(t *testing.T, mode string) {
			lockedPutResp, err := putObjectWithRetention(ctx, client, bucket, objKey1, mode, retainUntil)
			require.NoError(t, err)

			lockedGetResp, err := getObject(ctx, client, bucket, objKey1, *lockedPutResp.VersionId)
			require.NoError(t, err)
			require.Equal(t, mode, *lockedGetResp.ObjectLockMode)
			require.WithinDuration(t, retainUntil, *lockedGetResp.ObjectLockRetainUntilDate, time.Minute)

			unlockedPutResp, err := putObject(ctx, client, bucket, objKey1, nil)
			require.NoError(t, err)

			unlockedGetResp, err := getObject(ctx, client, bucket, objKey1, *unlockedPutResp.VersionId)
			require.NoError(t, err)
			require.Nil(t, unlockedGetResp.ObjectLockMode)
			require.Nil(t, unlockedGetResp.ObjectLockRetainUntilDate)

			legalHoldPutResp, err := putObjectWithLegalHold(ctx, client, bucket, objKey1, legalHoldOn)
			require.NoError(t, err)

			legalHoldGetResp, err := getObject(ctx, client, bucket, objKey1, *legalHoldPutResp.VersionId)
			require.NoError(t, err)
			require.Nil(t, legalHoldGetResp.ObjectLockMode)
			require.Nil(t, legalHoldGetResp.ObjectLockRetainUntilDate)
			require.Equal(t, legalHoldOn, *legalHoldGetResp.ObjectLockLegalHoldStatus)

			requireS3Error(t, deleteObject(ctx, client, bucket, objKey1, *lockedPutResp.VersionId), http.StatusForbidden, "AccessDenied")
			require.NoError(t, deleteObject(ctx, client, bucket, objKey1, *unlockedPutResp.VersionId))
			requireS3Error(t, deleteObject(ctx, client, bucket, objKey1, *legalHoldPutResp.VersionId), http.StatusForbidden, "AccessDenied")
		})

		t.Run("multi delete with locked and unlocked versions", func(t *testing.T) {
			putResp1, err := putObject(ctx, client, bucket, objKey1, nil)
			require.NoError(t, err)

			putResp2, err := putObject(ctx, client, bucket, objKey2, nil)
			require.NoError(t, err)

			obj1Version := putResp1.VersionId
			obj2Version := putResp2.VersionId

			_, err = putObjectRetention(ctx, client, bucket, objKey1, lockModeGovernance, retainUntil, "")
			require.NoError(t, err)

			deleteResp, err := client.DeleteObjectsWithContext(ctx, &s3.DeleteObjectsInput{
				Bucket: aws.String(bucket),
				Delete: &s3.Delete{
					Objects: []*s3.ObjectIdentifier{
						{
							Key:       aws.String(objKey1),
							VersionId: obj1Version,
						},
						{
							Key:       aws.String(objKey2),
							VersionId: obj2Version,
						},
					},
				},
			})
			require.NoError(t, err)

			require.Len(t, deleteResp.Deleted, 1)
			require.Len(t, deleteResp.Errors, 1)

			require.Equal(t, objKey2, *deleteResp.Deleted[0].Key)
			require.Equal(t, obj2Version, deleteResp.Deleted[0].VersionId)

			require.Equal(t, "AccessDenied", *deleteResp.Errors[0].Code)
			require.Equal(t, objKey1, *deleteResp.Errors[0].Key)
			require.Equal(t, obj1Version, deleteResp.Errors[0].VersionId)

			deleteResp, err = client.DeleteObjectsWithContext(ctx, &s3.DeleteObjectsInput{
				Bucket: aws.String(bucket),
				Delete: &s3.Delete{
					Objects: []*s3.ObjectIdentifier{
						{
							Key:       aws.String(objKey1),
							VersionId: obj1Version,
						},
					},
				},
				BypassGovernanceRetention: aws.Bool(true),
			})
			require.NoError(t, err)

			require.Len(t, deleteResp.Deleted, 1)
			require.Len(t, deleteResp.Errors, 0)

			require.Equal(t, objKey1, *deleteResp.Deleted[0].Key)
			require.Equal(t, obj1Version, deleteResp.Deleted[0].VersionId)
		})
	})
}

func TestAccessLogs(t *testing.T) {
	t.Parallel()

	runTest(t, testplanet.Config{
		SatelliteCount:   1,
		StorageNodeCount: 1,
		UplinkCount:      1,
	}, func(ctx *testcontext.Context, planet *testplanet.Planet, gwConfig *server.Config) {
		require.NoError(t, planet.Uplinks[0].CreateBucket(ctx, planet.Satellites[0], "destbucket"))

		logsAccess, err := planet.Uplinks[0].Access[planet.Satellites[0].ID()].Share(uplink.Permission{
			AllowUpload: true,
		}, uplink.SharePrefix{
			Bucket: "destbucket",
			Prefix: "logs",
		})
		require.NoError(t, err)

		accessLogConfig, err := middleware.SerializeAccessLogConfig(middleware.AccessLogConfig{
			middleware.WatchedBucket{
				ProjectID:  planet.Uplinks[0].Projects[0].PublicID,
				BucketName: "watchedbucket",
			}: middleware.DestinationLogBucket{
				BucketName: "destbucket",
				Storage:    serveraccesslogs.NewStorjStorage(logsAccess),
				Prefix:     "logs/",
			},
		})
		require.NoError(t, err)
		gwConfig.ServerAccessLogging = accessLogConfig
	}, func(ctx *testcontext.Context, planet *testplanet.Planet, gateway *server.Peer, auth *auth.Peer, creds register.Credentials) {
		client := createS3Client(t, gateway.Address(), creds.AccessKeyID, creds.SecretKey)

		require.NoError(t, createBucket(ctx, client, "watchedbucket", false, false))

		_, err := client.ListObjectsWithContext(ctx, &s3.ListObjectsInput{Bucket: aws.String("watchedbucket")})
		require.NoError(t, err)

		testFilePath := ctx.File("random1.dat")
		require.NoError(t, os.WriteFile(testFilePath, testrand.Bytes(123), 0600))

		testFile, err := os.Open(testFilePath)
		require.NoError(t, err)

		_, err = putObject(ctx, client, "watchedbucket", "testfile/random1.dat", testFile)
		require.NoError(t, err)

		_, err = getObject(ctx, client, "watchedbucket", "testfile/random1.dat", "")
		require.NoError(t, err)

		require.NoError(t, deleteObject(ctx, client, "watchedbucket", "testfile/random1.dat", ""))

		_, err = client.DeleteBucketWithContext(ctx, &s3.DeleteBucketInput{Bucket: aws.String("watchedbucket")})
		require.NoError(t, err)

		// force the gateway to close so we flush out all logs
		ctx.Check(gateway.Close)

		project, err := planet.Uplinks[0].GetProject(ctx, planet.Satellites[0])
		require.NoError(t, err)
		defer ctx.Check(project.Close)

		iter := project.ListObjects(ctx, "destbucket", &uplink.ListObjectsOptions{
			Prefix: "logs/",
		})

		var logs []string

		for iter.Next() {
			download, err := project.DownloadObject(ctx, "destbucket", iter.Item().Key, nil)
			require.NoError(t, err)

			var buf bytes.Buffer
			_, err = sync2.Copy(ctx, &buf, download)
			require.NoError(t, err)
			ctx.Check(download.Close)

			entries := strings.Split(buf.String(), "\n")

			// remove the last entry as it's always empty due to trailing newline
			logs = append(logs, entries[:len(entries)-1]...)
		}

		// todo: reverse parse of string back into struct in s3.go?
		require.Len(t, logs, 6)

		require.Contains(t, logs[0], "PUT /watchedbucket HTTP/1.1")
		require.Contains(t, logs[1], "GET /watchedbucket HTTP/1.1")
		require.Contains(t, logs[2], "PUT /watchedbucket/testfile/random1.dat HTTP/1.1")
		require.Contains(t, logs[3], "GET /watchedbucket/testfile/random1.dat HTTP/1.1")
		require.Contains(t, logs[3], "123")
		require.Contains(t, logs[4], "DELETE /watchedbucket/testfile/random1.dat HTTP/1.1")
		require.Contains(t, logs[5], "DELETE /watchedbucket HTTP/1.1")
	})
}

func TestUploadDownload(t *testing.T) {
	t.Parallel()

	runTest(t, testplanet.Config{
		SatelliteCount:   1,
		StorageNodeCount: 4,
		UplinkCount:      1,
		Reconfigure: testplanet.Reconfigure{
			Satellite: func(log *zap.Logger, index int, config *satellite.Config) {
				require.NoError(t, config.Placement.Set("config_test.yaml"))
			},
		},
	}, nil, func(ctx *testcontext.Context, planet *testplanet.Planet, gateway *server.Peer, auth *auth.Peer, creds register.Credentials) {
		client, err := minioclient.NewMinio(minioclient.Config{
			S3Gateway: gateway.Address(),
			Satellite: planet.Satellites[0].Addr(),
			AccessKey: creds.AccessKeyID,
			SecretKey: creds.SecretKey,
			APIKey:    planet.Uplinks[0].APIKey[planet.Satellites[0].ID()].Serialize(),
			NoSSL:     true,
		})
		require.NoError(t, err)

		{ // normal upload
			bucket := "bucket"

			err = client.MakeBucket(ctx, bucket, "")
			require.NoError(t, err)

			// generate enough data for a remote segment
			data := testrand.BytesInt(5000)
			objectName := "testdata"

			err = client.Upload(ctx, bucket, objectName, data)
			require.NoError(t, err)

			buffer := make([]byte, len(data))

			bytes, err := client.Download(ctx, bucket, objectName, buffer)
			require.NoError(t, err)

			require.Equal(t, data, bytes)
		}

		{ // multipart upload
			bucket := "bucket-multipart"

			err = client.MakeBucket(ctx, bucket, "")
			require.NoError(t, err)

			// minimum single part size is 5mib
			size := 8 * memory.MiB
			data := testrand.Bytes(size)
			objectName := "testdata"
			partSize := 5 * memory.MiB

			part1MD5 := md5.Sum(data[:partSize])
			part2MD5 := md5.Sum(data[partSize:])
			parts := append([]byte{}, part1MD5[:]...)
			parts = append(parts, part2MD5[:]...)
			partsMD5 := md5.Sum(parts)
			expectedETag := hex.EncodeToString(partsMD5[:]) + "-2"

			rawClient, ok := client.(*minioclient.Minio)
			require.True(t, ok)

			expectedMetadata := map[string]string{
				"foo": "bar",
			}
			err = rawClient.UploadMultipart(ctx, bucket, objectName, data, partSize.Int(), 0, expectedMetadata)
			require.NoError(t, err)

			// TODO find out why with prefix set its hanging test
			for objInfo := range rawClient.API.ListObjects(ctx, bucket, minio.ListObjectsOptions{Prefix: "", WithMetadata: true}) {
				require.Equal(t, objectName, objInfo.Key)

				// Minio adds a double quote to ETag, sometimes.
				// Remove the potential quote from either end.
				etag := strings.TrimPrefix(objInfo.ETag, `"`)
				etag = strings.TrimSuffix(etag, `"`)

				require.Equal(t, expectedETag, etag)
				// returned metadata is not fully processed so lets compare only single entry
				require.Equal(t, "bar", objInfo.UserMetadata["X-Amz-Meta-Foo"])
				break
			}

			object, err := rawClient.API.StatObject(ctx, bucket, objectName, minio.StatObjectOptions{})
			require.NoError(t, err)
			// TODO figure out why it returns "Foo:bar", instead "foo:bar"
			require.EqualValues(t, map[string]string{
				"Foo": "bar",
			}, object.UserMetadata)

			buffer := make([]byte, len(data))
			bytes, err := client.Download(ctx, bucket, objectName, buffer)
			require.NoError(t, err)

			require.Equal(t, data, bytes)
		}
		{
			// minio client has default minio user-agent set. On the
			// server-side, it has a partner ID associated with minio user-agent
			// string. Here we are checking if the corresponding partner ID is
			// set on the bucket created by using minio client
			uplink := planet.Uplinks[0]
			satellite := planet.Satellites[0]
			info, err := satellite.DB.Buckets().GetBucket(ctx, []byte("bucket"), uplink.Projects[0].ID)
			require.NoError(t, err)
			require.Contains(t, string(info.UserAgent), "Gateway-MT")

			// operating with aws-ask-go that has a default user-agent string
			// set for aws
			s3Client := createS3Client(t, gateway.Address(), creds.AccessKeyID, creds.SecretKey)

			_, err = s3Client.CreateBucketWithContext(ctx, &s3.CreateBucketInput{
				Bucket: aws.String("aws-bucket"),
			})
			require.NoError(t, err)

			// making sure the partner ID associated with the bucket created
			// using aws-sdk-go has a different partnerID than the bucket
			// created using minio client
			infoWithCustomUserAgent, err := satellite.DB.Buckets().GetBucket(ctx, []byte("aws-bucket"), uplink.Projects[0].ID)
			require.NoError(t, err)
			require.Contains(t, string(infoWithCustomUserAgent.UserAgent), "Gateway-MT")
		}
		{ // ListBucketsWithAttribution
			rawClient, ok := client.(*minioclient.Minio)
			require.True(t, ok)
			rawClient.API.SetAppInfo("attributionTest", "1.0")
			err = client.MakeBucket(ctx, "bucket-attribution1", "")
			require.NoError(t, err)
			rawClient.API.SetAppInfo("testAttribution", "1.0")
			err = client.MakeBucket(ctx, "bucket-attribution2", "")
			require.NoError(t, err)

			resp, err := client.ListBucketsAttribution(ctx)
			require.NoError(t, err)
			res := strings.Join(resp, ",")
			require.Contains(t, res, "attributionTest")
			require.Contains(t, res, "testAttribution")
		}
		{ // GetBucketLocation
			_, err = client.GetBucketLocation(ctx, "bucket-without-location-set")
			require.True(t, minioclient.MinioError.Has(err))
			require.ErrorAs(t, err, &minio.ErrorResponse{
				StatusCode: 404,
				Code:       "NoSuchBucket",
				Message:    "The specified bucket does not exist.",
				BucketName: "bucket-without-location-set",
			})

			// MinIO's SDK will cache the newly created bucket's location, and
			// since we make it with an empty location for which it will supply
			// "us-east-1" (or something else; the problem is that it will
			// always supply something there and cache it), we need to create it
			// low-level if we want to circumvent the impossible-to-disable
			// cache to force the request to the gateway.
			require.NoError(t, planet.Uplinks[0].CreateBucket(ctx, planet.Satellites[0], "bucket-without-location-set"))

			location, err := client.GetBucketLocation(ctx, "bucket-without-location-set")
			require.NoError(t, err)
			require.Equal(t, "global", location)

			require.NoError(t, planet.Uplinks[0].CreateBucket(ctx, planet.Satellites[0], "bucket-with-location-set"))

			_, err = planet.Satellites[0].DB.Buckets().UpdateBucket(ctx, buckets.Bucket{
				ProjectID: planet.Uplinks[0].Projects[0].ID,
				Name:      "bucket-with-location-set",
				Placement: storj.PlacementConstraint(44),
			})
			require.NoError(t, err)

			location, err = client.GetBucketLocation(ctx, "bucket-with-location-set")
			require.NoError(t, err)
			require.Equal(t, "Poland", location)
		}
	})
}

func TestVersioning(t *testing.T) {
	t.Parallel()

	runTest(t, testplanet.Config{
		SatelliteCount:   1,
		StorageNodeCount: 4,
		UplinkCount:      1,
		Reconfigure: testplanet.Reconfigure{
			Satellite: func(log *zap.Logger, index int, config *satellite.Config) {
				config.Metainfo.UseBucketLevelObjectVersioning = true
			},
		},
	}, nil, func(ctx *testcontext.Context, planet *testplanet.Planet, gateway *server.Peer, auth *auth.Peer, creds register.Credentials) {
		client, err := minioclient.NewMinio(minioclient.Config{
			S3Gateway: gateway.Address(),
			Satellite: planet.Satellites[0].Addr(),
			AccessKey: creds.AccessKeyID,
			SecretKey: creds.SecretKey,
			APIKey:    planet.Uplinks[0].APIKey[planet.Satellites[0].ID()].Serialize(),
			NoSSL:     true,
		})
		require.NoError(t, err)

		rawClient, ok := client.(*minioclient.Minio)
		require.True(t, ok)

		t.Run("bucket versioning enabling-disabling", func(t *testing.T) {
			bucket := "bucket"
			err = rawClient.API.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
			require.NoError(t, err)

			v, err := rawClient.API.GetBucketVersioning(ctx, bucket)
			require.NoError(t, err)
			require.Empty(t, v.Status)

			require.NoError(t, rawClient.API.EnableVersioning(ctx, bucket))

			v, err = rawClient.API.GetBucketVersioning(ctx, bucket)
			require.NoError(t, err)
			require.EqualValues(t, versioning.Enabled, v.Status)

			require.NoError(t, rawClient.API.SuspendVersioning(ctx, bucket))

			v, err = rawClient.API.GetBucketVersioning(ctx, bucket)
			require.NoError(t, err)
			require.EqualValues(t, versioning.Suspended, v.Status)
		})

		t.Run("check VersionID support for different methods", func(t *testing.T) {
			bucket := testrand.BucketName()

			require.NoError(t, rawClient.API.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}))
			require.NoError(t, rawClient.API.EnableVersioning(ctx, bucket))

			// upload first version
			expectedContentA1 := testrand.Bytes(5 * memory.KiB)
			uploadInfo, err := rawClient.API.PutObject(ctx, bucket, "objectA", bytes.NewReader(expectedContentA1), int64(len(expectedContentA1)), minio.PutObjectOptions{})
			require.NoError(t, err)
			require.NotEmpty(t, uploadInfo.VersionID)

			objectA1VersionID := uploadInfo.VersionID

			statInfo, err := rawClient.API.StatObject(ctx, bucket, "objectA", minio.GetObjectOptions{})
			require.NoError(t, err)
			require.Equal(t, objectA1VersionID, statInfo.VersionID)

			// the same request but with VersionID specified
			statInfo, err = rawClient.API.StatObject(ctx, bucket, "objectA", minio.GetObjectOptions{
				VersionID: objectA1VersionID,
			})
			require.NoError(t, err)
			require.Equal(t, objectA1VersionID, statInfo.VersionID)

			tags, err := tags.NewTags(map[string]string{
				"key1": "tag1",
			}, true)
			require.NoError(t, err)
			err = rawClient.API.PutObjectTagging(ctx, bucket, "objectA", tags, minio.PutObjectTaggingOptions{})
			require.NoError(t, err)

			// upload second version
			expectedContentA2 := testrand.Bytes(5 * memory.KiB)
			uploadInfo, err = rawClient.API.PutObject(ctx, bucket, "objectA", bytes.NewReader(expectedContentA2), int64(len(expectedContentA2)), minio.PutObjectOptions{})
			require.NoError(t, err)
			require.NotEmpty(t, uploadInfo.VersionID)

			objectA2VersionID := uploadInfo.VersionID

			statInfo, err = rawClient.API.StatObject(ctx, bucket, "objectA", minio.GetObjectOptions{})
			require.NoError(t, err)
			require.Equal(t, objectA2VersionID, statInfo.VersionID)

			// the same request but with VersionID specified
			statInfo, err = rawClient.API.StatObject(ctx, bucket, "objectA", minio.GetObjectOptions{
				VersionID: objectA2VersionID,
			})
			require.NoError(t, err)
			require.Equal(t, objectA2VersionID, statInfo.VersionID)

			// // check that we have two different versions
			object, err := rawClient.API.GetObject(ctx, bucket, "objectA", minio.GetObjectOptions{
				VersionID: objectA1VersionID,
			})
			require.NoError(t, err)

			contentA1, err := io.ReadAll(object)
			require.NoError(t, err)
			require.Equal(t, expectedContentA1, contentA1)

			object, err = rawClient.API.GetObject(ctx, bucket, "objectA", minio.GetObjectOptions{
				VersionID: objectA2VersionID,
			})
			require.NoError(t, err)

			contentA2, err := io.ReadAll(object)
			require.NoError(t, err)
			require.Equal(t, expectedContentA2, contentA2)

			tagsInfo, err := rawClient.API.GetObjectTagging(ctx, bucket, "objectA", minio.GetObjectTaggingOptions{
				VersionID: objectA1VersionID,
			})
			require.NoError(t, err)
			require.EqualValues(t, tags.ToMap(), tagsInfo.ToMap())

			// TODO(ver): add test for setting tag for specific version when implemented
		})

		t.Run("check VersionID while completing multipart upload", func(t *testing.T) {
			bucket := testrand.BucketName()

			require.NoError(t, rawClient.API.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}))
			require.NoError(t, rawClient.API.EnableVersioning(ctx, bucket))

			expectedContent := testrand.Bytes(500 * memory.KiB)
			uploadInfo, err := rawClient.API.PutObject(ctx, bucket, "objectA", bytes.NewReader(expectedContent), -1, minio.PutObjectOptions{})
			require.NoError(t, err)
			require.NotEmpty(t, uploadInfo.VersionID)
		})

		t.Run("check VersionID with delete object and delete objects", func(t *testing.T) {
			bucket := testrand.BucketName()

			require.NoError(t, rawClient.API.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}))
			require.NoError(t, rawClient.API.EnableVersioning(ctx, bucket))

			versionIDs := make([]string, 5)

			for i := range versionIDs {
				expectedContent := testrand.Bytes(5 * memory.KiB)
				uploadInfo, err := rawClient.API.PutObject(ctx, bucket, "objectA", bytes.NewReader(expectedContent), int64(len(expectedContent)), minio.PutObjectOptions{})
				require.NoError(t, err)
				require.NotEmpty(t, uploadInfo.VersionID)
				versionIDs[i] = uploadInfo.VersionID
			}

			err := rawClient.API.RemoveObject(ctx, bucket, "objectA", minio.RemoveObjectOptions{
				VersionID: versionIDs[0],
			})
			require.NoError(t, err)

			objectsCh := make(chan minio.ObjectInfo)
			ctx.Go(func() error {
				defer close(objectsCh)
				for _, versionID := range versionIDs[1:] {
					objectsCh <- minio.ObjectInfo{
						Key:       "objectA",
						VersionID: versionID,
					}
				}
				return nil
			})

			errorCh := rawClient.API.RemoveObjects(ctx, bucket, objectsCh, minio.RemoveObjectsOptions{})
			for e := range errorCh {
				require.NoError(t, e.Err)
			}

			// TODO(ver): replace with ListObjectVersions when implemented
			for _, versionID := range versionIDs {
				_, err := rawClient.API.StatObject(ctx, bucket, "objectA", minio.GetObjectOptions{
					VersionID: versionID,
				})
				require.Error(t, err)
				require.Equal(t, "NoSuchKey", minio.ToErrorResponse(err).Code)
			}
		})

		t.Run("ListObjectVersions", func(t *testing.T) {
			bucket := testrand.BucketName()

			require.NoError(t, rawClient.API.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}))
			require.NoError(t, rawClient.API.EnableVersioning(ctx, bucket))

			for range rawClient.API.ListObjects(ctx, bucket, minio.ListObjectsOptions{
				WithVersions: true,
			}) {
				require.Fail(t, "no objects to list")
			}

			expectedContent := testrand.Bytes(5 * memory.KiB)
			_, err := rawClient.API.PutObject(ctx, bucket, "objectA", bytes.NewReader(expectedContent), int64(len(expectedContent)), minio.PutObjectOptions{})
			require.NoError(t, err)

			err = rawClient.API.RemoveObject(ctx, bucket, "objectA", minio.RemoveObjectOptions{})
			require.NoError(t, err)

			_, err = rawClient.API.PutObject(ctx, bucket, "objectA", bytes.NewReader(expectedContent), int64(len(expectedContent)), minio.PutObjectOptions{})
			require.NoError(t, err)

			err = rawClient.API.RemoveObject(ctx, bucket, "objectA", minio.RemoveObjectOptions{})
			require.NoError(t, err)

			_, err = rawClient.API.PutObject(ctx, bucket, "objectA", bytes.NewReader(expectedContent), int64(len(expectedContent)), minio.PutObjectOptions{})
			require.NoError(t, err)

			listedObjects := 0
			listedDeleteMarkers := 0
			for objectInfo := range rawClient.API.ListObjects(ctx, bucket, minio.ListObjectsOptions{
				WithVersions: true,
			}) {
				if objectInfo.IsDeleteMarker {
					listedDeleteMarkers++
				} else {
					listedObjects++
				}
			}
			require.Equal(t, 2, listedDeleteMarkers)
			require.Equal(t, 3, listedObjects)

			// TODO(ver): add tests to check listing order when will be fixed on satellite side: https://github.com/storj/storj/issues/6550
		})
	})
}

func TestObjectAttributes(t *testing.T) {
	t.Parallel()

	runTest(t, testplanet.Config{
		SatelliteCount:   1,
		StorageNodeCount: 1,
		UplinkCount:      1,
		Reconfigure: testplanet.Reconfigure{
			Satellite: func(log *zap.Logger, index int, config *satellite.Config) {
				config.Metainfo.UseBucketLevelObjectVersioning = true
			},
		},
	}, nil, func(ctx *testcontext.Context, planet *testplanet.Planet, gateway *server.Peer, auth *auth.Peer, creds register.Credentials) {
		client := createS3Client(t, gateway.Address(), creds.AccessKeyID, creds.SecretKey)

		bucket := testrand.BucketName()
		require.NoError(t, createBucket(ctx, client, bucket, true, false))

		unversionedBucket := testrand.BucketName()
		require.NoError(t, createBucket(ctx, client, unversionedBucket, false, false))

		testFilePath := ctx.File("random1.dat")
		require.NoError(t, os.WriteFile(testFilePath, testrand.Bytes(123), 0600))

		testFile, err := os.Open(testFilePath)
		require.NoError(t, err)

		putResp, err := putObject(ctx, client, bucket, "object1", testFile)
		require.NoError(t, err)

		_, err = putObject(ctx, client, unversionedBucket, "object1", testFile)
		require.NoError(t, err)

		_, err = getObjectAttributes(ctx, client, bucket, "objectnonexistent", "", []*string{
			aws.String("ETag"),
		})
		requireS3Error(t, err, http.StatusNotFound, "NoSuchKey")

		_, err = getObjectAttributes(ctx, client, bucket, "object1", "abc123", []*string{
			aws.String("ETag"),
		})
		requireS3Error(t, err, http.StatusBadRequest, "InvalidArgument")

		_, err = getObjectAttributes(ctx, client, bucket, "object1", "", []*string{
			aws.String("Invalid"),
		})
		requireS3Error(t, err, http.StatusBadRequest, "InvalidArgument")

		attrResp, err := getObjectAttributes(ctx, client, unversionedBucket, "object1", "", []*string{
			aws.String("ObjectSize"),
		})
		require.NoError(t, err)
		require.Empty(t, attrResp.VersionId)

		attrResp, err = getObjectAttributes(ctx, client, bucket, "object1", "", []*string{
			aws.String("ETag"),
			aws.String("ObjectSize"),
			aws.String("StorageClass"),
		})
		require.NoError(t, err)

		require.Equal(t, putResp.VersionId, attrResp.VersionId)

		// ETag should really be double quoted everywhere by the spec, but GetObjectAttributes
		// is inconsistent with other S3 APIs that do return it quoted.
		require.Equal(t, regexp.MustCompile(`^"(.*)"$`).ReplaceAllString(*putResp.ETag, `$1`), *attrResp.ETag)
		require.Equal(t, aws.Int64(123), attrResp.ObjectSize)
		require.Equal(t, aws.String(s3.ObjectStorageClassStandard), attrResp.StorageClass)
		require.Empty(t, attrResp.DeleteMarker)

		attrResp, err = getObjectAttributes(ctx, client, bucket, "object1", *putResp.VersionId, []*string{
			aws.String("ObjectSize"),
		})
		require.NoError(t, err)

		require.Equal(t, putResp.VersionId, attrResp.VersionId)
		require.Equal(t, aws.Int64(123), attrResp.ObjectSize)
		require.Empty(t, attrResp.ETag)
		require.Empty(t, attrResp.StorageClass)
		require.Empty(t, attrResp.DeleteMarker)
	})
}

func TestConditionalWrites(t *testing.T) {
	t.Parallel()

	runTest(t, testplanet.Config{
		SatelliteCount:   1,
		StorageNodeCount: 1,
		UplinkCount:      1,
		Reconfigure: testplanet.Reconfigure{
			Satellite: func(log *zap.Logger, index int, config *satellite.Config) {
				config.Metainfo.UseBucketLevelObjectVersioning = true
			},
		},
	}, nil, func(ctx *testcontext.Context, planet *testplanet.Planet, gateway *server.Peer, auth *auth.Peer, creds register.Credentials) {
		client := createS3Client(t, gateway.Address(), creds.AccessKeyID, creds.SecretKey)

		unversionedBucket, versionedBucket := testrand.BucketName(), testrand.BucketName()
		require.NoError(t, createBucket(ctx, client, unversionedBucket, false, false))
		require.NoError(t, createBucket(ctx, client, versionedBucket, true, false))

		runSubTest := func(name string, fn func(t *testing.T, bucket, key string)) {
			for _, tc := range []struct {
				name, bucket string
			}{
				{name: "unversioned bucket", bucket: unversionedBucket},
				{name: "versioned bucket", bucket: versionedBucket},
			} {
				t.Run(fmt.Sprintf("%s %s", name, tc.name), func(t *testing.T) {
					// todo: testrand.Path() throws a signature validation error on gateway (see https://github.com/storj/edge/issues/572)
					fn(t, tc.bucket, string(testrand.RandAlphaNumeric(16)))
				})
			}
		}

		runSubTestWithBody := func(name string, fn func(t *testing.T, bucket, key string, body io.ReadSeeker)) {
			runSubTest(name, func(t *testing.T, bucket, key string) {
				for _, tc := range []struct {
					name string
					body io.ReadSeeker
				}{
					{name: "inline", body: bytes.NewReader(testrand.Bytes(100 * memory.B))},
					{name: "non-inline", body: bytes.NewReader(testrand.Bytes(5 * memory.MiB))},
				} {
					t.Run(tc.name, func(t *testing.T) {
						// todo: testrand.Path() throws a signature validation error on gateway (see https://github.com/storj/edge/issues/572)
						fn(t, bucket, string(testrand.RandAlphaNumeric(16)), tc.body)
					})
				}
			})
		}

		doPutRequest := func(ctx context.Context, bucket, key string, body io.ReadSeeker, ifNoneMatch string) error {
			req, _ := client.PutObjectRequest(&s3.PutObjectInput{
				Bucket: aws.String(bucket),
				Key:    aws.String(key),
				Body:   body,
			})
			req.SetContext(ctx)
			req.HTTPRequest.Header.Set("If-None-Match", ifNoneMatch)
			return req.Send()
		}

		doCopyRequest := func(ctx context.Context, srcBucket, srcKey, dstBucket, dstKey string, ifNoneMatch string) error {
			req, _ := client.CopyObjectRequest(&s3.CopyObjectInput{
				Bucket:     aws.String(dstBucket),
				Key:        aws.String(dstKey),
				CopySource: aws.String(srcBucket + "/" + srcKey),
			})
			req.SetContext(ctx)
			req.HTTPRequest.Header.Set("If-None-Match", ifNoneMatch)
			return req.Send()
		}

		newUpload := func(bucket, key string, body io.ReadSeeker) (*string, []*s3.CompletedPart) {
			uploadResp, err := client.CreateMultipartUploadWithContext(ctx, &s3.CreateMultipartUploadInput{
				Bucket: aws.String(bucket),
				Key:    aws.String(key),
			})
			require.NoError(t, err)

			partResp, err := client.UploadPartWithContext(ctx, &s3.UploadPartInput{
				Bucket:     aws.String(bucket),
				Key:        aws.String(key),
				PartNumber: aws.Int64(1),
				UploadId:   uploadResp.UploadId,
				Body:       body,
			})
			require.NoError(t, err)

			return uploadResp.UploadId, []*s3.CompletedPart{
				{
					PartNumber: aws.Int64(1),
					ETag:       partResp.ETag,
				},
			}
		}

		completeUpload := func(bucket, key string, uploadID *string, completedParts []*s3.CompletedPart, ifNoneMatch string) error {
			req, _ := client.CompleteMultipartUploadRequest(&s3.CompleteMultipartUploadInput{
				Bucket:   aws.String(bucket),
				Key:      aws.String(key),
				UploadId: uploadID,
				MultipartUpload: &s3.CompletedMultipartUpload{
					Parts: completedParts,
				},
			})
			req.SetContext(ctx)
			req.HTTPRequest.Header.Set("If-None-Match", ifNoneMatch)
			return req.Send()
		}

		runSubTest("Unimplemented PutObject", func(t *testing.T, bucket, key string) {
			requireS3Error(t, doPutRequest(ctx, bucket, key, nil, "something"), http.StatusNotImplemented, "NotImplemented")
		})

		runSubTest("Unimplemented CopyObject", func(t *testing.T, bucket, key string) {
			require.NoError(t, doPutRequest(ctx, bucket, key, nil, "*"))
			requireS3Error(t, doCopyRequest(ctx, bucket, key, bucket, key+"-copy", "something"), http.StatusNotImplemented, "NotImplemented")
		})

		runSubTest("Unimplemented CompleteMultipartUpload", func(t *testing.T, bucket, key string) {
			uploadID, completedParts := newUpload(bucket, key, nil)
			requireS3Error(t, completeUpload(bucket, key, uploadID, completedParts, "something"), http.StatusNotImplemented, "NotImplemented")
		})

		runSubTestWithBody("PutObject", func(t *testing.T, bucket, key string, body io.ReadSeeker) {
			require.NoError(t, doPutRequest(ctx, bucket, key, body, "*"))
			requireS3Error(t, doPutRequest(ctx, bucket, key, body, "*"), http.StatusPreconditionFailed, "PreconditionFailed")
			require.NoError(t, deleteObject(ctx, client, bucket, key, ""))
			require.NoError(t, doPutRequest(ctx, bucket, key, body, "*"))
		})

		runSubTest("PutObject concurrent", func(t *testing.T, bucket, key string) {
			for _, impl := range planet.Satellites[0].DB.Testing().Implementation() {
				if impl == dbutil.Postgres {
					t.Skip("todo: flaky test")
				}
			}

			var group errs2.Group
			group.Go(func() error {
				return doPutRequest(ctx, bucket, key, bytes.NewReader(testrand.Bytes(100*memory.B)), "*")
			})
			group.Go(func() error {
				return doPutRequest(ctx, bucket, key, bytes.NewReader(testrand.Bytes(100*memory.B)), "*")
			})
			errs := group.Wait()
			require.Len(t, errs, 1)
			requireS3Error(t, errs[0], http.StatusPreconditionFailed, "PreconditionFailed")
		})

		runSubTestWithBody("CopyObject", func(t *testing.T, bucket, key string, body io.ReadSeeker) {
			srcKey, dstKey := key, key+"-copy"

			require.NoError(t, doPutRequest(ctx, bucket, srcKey, body, "*"))
			require.NoError(t, doCopyRequest(ctx, bucket, srcKey, bucket, dstKey, "*"))
			requireS3Error(t, doCopyRequest(ctx, bucket, srcKey, bucket, dstKey, "*"), http.StatusPreconditionFailed, "PreconditionFailed")
			require.NoError(t, deleteObject(ctx, client, bucket, dstKey, ""))
			require.NoError(t, doCopyRequest(ctx, bucket, srcKey, bucket, dstKey, "*"))
		})

		runSubTest("CompleteMultipartUpload", func(t *testing.T, bucket, key string) {
			uploadID, completedParts := newUpload(bucket, key, nil)
			require.NoError(t, completeUpload(bucket, key, uploadID, completedParts, "*"))

			uploadID, completedParts = newUpload(bucket, key, nil)
			requireS3Error(t, completeUpload(bucket, key, uploadID, completedParts, "*"), http.StatusPreconditionFailed, "PreconditionFailed")

			require.NoError(t, deleteObject(ctx, client, bucket, key, ""))

			uploadID, completedParts = newUpload(bucket, key, nil)
			require.NoError(t, completeUpload(bucket, key, uploadID, completedParts, "*"))
		})

		runSubTest("CompleteMultipartUpload concurrent", func(t *testing.T, bucket, key string) {
			for _, impl := range planet.Satellites[0].DB.Testing().Implementation() {
				if impl == dbutil.Postgres {
					t.Skip("todo: flaky test")
				}
			}

			uploadID1, completedParts1 := newUpload(bucket, key, nil)
			uploadID2, completedParts2 := newUpload(bucket, key, nil)

			var group errs2.Group
			group.Go(func() error { return completeUpload(bucket, key, uploadID1, completedParts1, "*") })
			group.Go(func() error { return completeUpload(bucket, key, uploadID2, completedParts2, "*") })
			errs := group.Wait()
			require.Len(t, errs, 1)
			requireS3Error(t, errs[0], http.StatusPreconditionFailed, "PreconditionFailed")
		})
	})
}

func runTest(
	t *testing.T,
	planetConfig testplanet.Config,
	prepare func(ctx *testcontext.Context, planet *testplanet.Planet, gwConfig *server.Config),
	test func(ctx *testcontext.Context, planet *testplanet.Planet, gateway *server.Peer, auth *auth.Peer, creds register.Credentials),
) {
	testplanet.Run(t, planetConfig, func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet) {
		var gwConfig server.Config
		cfgstruct.Bind(&pflag.FlagSet{}, &gwConfig, cfgstruct.UseTestDefaults())

		var authConfig auth.Config
		cfgstruct.Bind(&pflag.FlagSet{}, &authConfig, cfgstruct.UseTestDefaults())

		if prepare != nil {
			prepare(ctx, planet, &gwConfig)
		}

		logger := zaptest.NewLogger(t)
		defer ctx.Check(logger.Sync)

		spanner, err := spannerauthtest.ConfigureTestServer(ctx, logger)
		require.NoError(t, err)
		defer spanner.Close()

		// Set a dummy endpoint so we don't have to hardcode port numbers.
		// Endpoint is only used by authservice to indicate to clients where
		// the gateway is, so we don't really care, and would rather have
		// auto-assigned port numbers.
		authConfig.Endpoint = "http://127.0.0.1:12345"
		authConfig.AuthToken = []string{"super-secret"}
		authConfig.AllowedSatellites = []string{planet.Satellites[0].NodeURL().String()}
		authConfig.KVBackend = "spanner://"
		authConfig.ListenAddr = "127.0.0.1:0"
		authConfig.DRPCListenAddr = "127.0.0.1:0"
		authConfig.Spanner = spannerauth.Config{
			DatabaseName: "projects/P/instances/I/databases/D",
			Address:      spanner.Addr,
		}
		authConfig.RetrievePublicProjectID = true

		auth, err := auth.New(ctx, zaptest.NewLogger(t).Named("auth"), authConfig, fpath.ApplicationDir("storj", "authservice"))
		require.NoError(t, err)

		// auth peer needs to be canceled to shut the servers down.
		cancelCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		ctx.Go(func() error {
			defer ctx.Check(auth.Close)
			return errs2.IgnoreCanceled(auth.Run(cancelCtx))
		})

		gwConfig.Server.Address = "127.0.0.1:0"
		gwConfig.Auth = authclient.Config{
			BaseURL: "http://" + auth.Address(),
			Token:   "super-secret",
		}
		gwConfig.InsecureLogAll = true

		authClient := authclient.New(gwConfig.Auth)

		gateway, err := server.New(gwConfig, zaptest.NewLogger(t).Named("gateway"), trustedip.NewListTrustAll(), []string{}, authClient, 10)
		require.NoError(t, err)

		defer ctx.Check(gateway.Close)

		serialized, err := planet.Uplinks[0].Access[planet.Satellites[0].ID()].Serialize()
		require.NoError(t, err)

		creds, err := register.Access(ctx, "http://"+auth.Address(), serialized, false)
		require.NoError(t, err)

		// Set the correct endpoint now that we know where gateway is.
		creds.Endpoint = "http://" + gateway.Address()

		ctx.Go(func() error {
			return gateway.Run(ctx)
		})

		test(ctx, planet, gateway, auth, creds)
	})
}

func createS3Client(t *testing.T, gatewayAddr, accessKeyID, secretKey string) *s3.S3 {
	sess, err := session.NewSession(&aws.Config{
		Region:           aws.String("global"),
		Credentials:      credentials.NewStaticCredentials(accessKeyID, secretKey, ""),
		Endpoint:         aws.String("http://" + gatewayAddr),
		S3ForcePathStyle: aws.Bool(true),
	})
	require.NoError(t, err)

	return s3.New(sess)
}

func registerAccess(ctx context.Context, t *testing.T, encAccess *grant.EncryptionAccess, apiKey *macaroon.APIKey, satelliteAddr, authAddr string) register.Credentials {
	restrictedAccess := grant.Access{
		SatelliteAddress: satelliteAddr,
		APIKey:           apiKey,
		EncAccess:        encAccess,
	}

	serialized, err := restrictedAccess.Serialize()
	require.NoError(t, err)

	creds, err := register.Access(ctx, "http://"+authAddr, serialized, false)
	require.NoError(t, err)

	return creds
}

func createBucket(ctx context.Context, client *s3.S3, bucket string, versioningEnabled, lockEnabled bool) error {
	_, err := client.CreateBucketWithContext(ctx, &s3.CreateBucketInput{
		Bucket:                     aws.String(bucket),
		ObjectLockEnabledForBucket: aws.Bool(lockEnabled),
	})
	if err != nil {
		return err
	}

	if versioningEnabled {
		_, err = client.PutBucketVersioning(&s3.PutBucketVersioningInput{
			Bucket: aws.String(bucket),
			VersioningConfiguration: &s3.VersioningConfiguration{
				Status: aws.String(s3.BucketVersioningStatusEnabled),
			},
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func getObjectLockConfiguration(ctx context.Context, client *s3.S3, bucket string) (*s3.GetObjectLockConfigurationOutput, error) {
	return client.GetObjectLockConfigurationWithContext(ctx, &s3.GetObjectLockConfigurationInput{
		Bucket: aws.String(bucket),
	})
}

func putObjectLockConfiguration(ctx context.Context, client *s3.S3, bucket, enabledStatus string, rule *s3.ObjectLockRule) (*s3.PutObjectLockConfigurationOutput, error) {
	return client.PutObjectLockConfigurationWithContext(ctx, &s3.PutObjectLockConfigurationInput{
		Bucket: aws.String(bucket),
		ObjectLockConfiguration: &s3.ObjectLockConfiguration{
			ObjectLockEnabled: aws.String(enabledStatus),
			Rule:              rule,
		},
	})
}

func putObject(ctx context.Context, client *s3.S3, bucket, key string, body io.ReadSeeker) (*s3.PutObjectOutput, error) {
	return client.PutObjectWithContext(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   body,
	})
}

func putObjectLegalHold(ctx context.Context, client *s3.S3, bucket, key, status, versionID string) (*s3.PutObjectLegalHoldOutput, error) {
	input := s3.PutObjectLegalHoldInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		LegalHold: &s3.ObjectLockLegalHold{
			Status: aws.String(status),
		},
	}
	if versionID != "" {
		input.VersionId = aws.String(versionID)
	}
	return client.PutObjectLegalHoldWithContext(ctx, &input)
}

func getObjectLegalHold(ctx context.Context, client *s3.S3, bucket, key, versionID string) (*s3.GetObjectLegalHoldOutput, error) {
	input := s3.GetObjectLegalHoldInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}
	if versionID != "" {
		input.VersionId = aws.String(versionID)
	}
	return client.GetObjectLegalHoldWithContext(ctx, &input)
}

func putObjectWithRetention(ctx context.Context, client *s3.S3, bucket, key, mode string, retainUntil time.Time) (*s3.PutObjectOutput, error) {
	return client.PutObjectWithContext(ctx, &s3.PutObjectInput{
		Bucket:                    aws.String(bucket),
		Key:                       aws.String(key),
		ObjectLockMode:            aws.String(mode),
		ObjectLockRetainUntilDate: aws.Time(retainUntil),
	})
}

func putObjectMultipartWithRetention(ctx context.Context, client *s3.S3, bucket, key, mode string, retainUntil time.Time) (*s3.CompleteMultipartUploadOutput, error) {
	upload, err := client.CreateMultipartUploadWithContext(ctx, &s3.CreateMultipartUploadInput{
		Bucket:                    aws.String(bucket),
		Key:                       aws.String(key),
		ObjectLockMode:            aws.String(mode),
		ObjectLockRetainUntilDate: aws.Time(retainUntil),
	})
	if err != nil {
		return nil, err
	}

	part, err := client.UploadPartWithContext(ctx, &s3.UploadPartInput{
		Bucket:     aws.String(bucket),
		Key:        aws.String(key),
		UploadId:   upload.UploadId,
		PartNumber: aws.Int64(1),
		Body:       bytes.NewReader(testrand.Bytes(memory.KiB)),
	})
	if err != nil {
		return nil, err
	}

	return client.CompleteMultipartUploadWithContext(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		UploadId: upload.UploadId,
		MultipartUpload: &s3.CompletedMultipartUpload{
			Parts: []*s3.CompletedPart{
				{
					ETag:       part.ETag,
					PartNumber: aws.Int64(1),
				},
			},
		},
	})
}

func putObjectMultipartWithLegalHold(ctx context.Context, client *s3.S3, bucket, key, legalHoldStatus string) (*s3.CompleteMultipartUploadOutput, error) {
	upload, err := client.CreateMultipartUploadWithContext(ctx, &s3.CreateMultipartUploadInput{
		Bucket:                    aws.String(bucket),
		Key:                       aws.String(key),
		ObjectLockLegalHoldStatus: aws.String(legalHoldStatus),
	})
	if err != nil {
		return nil, err
	}

	part, err := client.UploadPartWithContext(ctx, &s3.UploadPartInput{
		Bucket:     aws.String(bucket),
		Key:        aws.String(key),
		UploadId:   upload.UploadId,
		PartNumber: aws.Int64(1),
		Body:       bytes.NewReader(testrand.Bytes(memory.KiB)),
	})
	if err != nil {
		return nil, err
	}

	return client.CompleteMultipartUploadWithContext(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		UploadId: upload.UploadId,
		MultipartUpload: &s3.CompletedMultipartUpload{
			Parts: []*s3.CompletedPart{
				{
					ETag:       part.ETag,
					PartNumber: aws.Int64(1),
				},
			},
		},
	})
}

func putObjectWithLegalHold(ctx context.Context, client *s3.S3, bucket, key, legalHoldStatus string) (*s3.PutObjectOutput, error) {
	return client.PutObjectWithContext(ctx, &s3.PutObjectInput{
		Bucket:                    aws.String(bucket),
		Key:                       aws.String(key),
		ObjectLockLegalHoldStatus: aws.String(legalHoldStatus),
	})
}

func putObjectWithLegalHoldAndRetention(ctx context.Context, client *s3.S3, bucket, key, legalHoldStatus, mode string, retainUntil time.Time) (*s3.PutObjectOutput, error) {
	return client.PutObjectWithContext(ctx, &s3.PutObjectInput{
		Bucket:                    aws.String(bucket),
		Key:                       aws.String(key),
		ObjectLockLegalHoldStatus: aws.String(legalHoldStatus),
		ObjectLockMode:            aws.String(mode),
		ObjectLockRetainUntilDate: aws.Time(retainUntil),
	})
}

func getObjectRetention(ctx context.Context, client *s3.S3, bucket, key, versionID string) (*s3.GetObjectRetentionOutput, error) {
	input := s3.GetObjectRetentionInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}
	if versionID != "" {
		input.VersionId = aws.String(versionID)
	}
	return client.GetObjectRetentionWithContext(ctx, &input)
}

func putObjectRetention(ctx context.Context, client *s3.S3, bucket, key, lockMode string, retainUntil time.Time, versionID string) (*s3.PutObjectRetentionOutput, error) {
	input := s3.PutObjectRetentionInput{
		Bucket:    aws.String(bucket),
		Key:       aws.String(key),
		Retention: &s3.ObjectLockRetention{},
	}
	if versionID != "" {
		input.VersionId = aws.String(versionID)
	}
	if lockMode != "" {
		input.Retention.Mode = aws.String(lockMode)
	}
	if !retainUntil.IsZero() {
		input.Retention.RetainUntilDate = aws.Time(retainUntil)
	}
	return client.PutObjectRetentionWithContext(ctx, &input)
}

func putObjectRetentionBypassGovernance(ctx context.Context, client *s3.S3, bucket, key, lockMode string, retainUntil time.Time, versionID string) (*s3.PutObjectRetentionOutput, error) {
	input := s3.PutObjectRetentionInput{
		Bucket:                    aws.String(bucket),
		Key:                       aws.String(key),
		BypassGovernanceRetention: aws.Bool(true),
		Retention:                 &s3.ObjectLockRetention{},
	}
	if versionID != "" {
		input.VersionId = aws.String(versionID)
	}
	if lockMode != "" {
		input.Retention.Mode = aws.String(lockMode)
	}
	if !retainUntil.IsZero() {
		input.Retention.RetainUntilDate = aws.Time(retainUntil)
	}
	return client.PutObjectRetentionWithContext(ctx, &input)
}

func getObject(ctx context.Context, client *s3.S3, bucket, key, versionID string) (*s3.GetObjectOutput, error) {
	input := s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}
	if versionID != "" {
		input.VersionId = aws.String(versionID)
	}
	return client.GetObjectWithContext(ctx, &input)
}

func getObjectAttributes(ctx context.Context, client *s3.S3, bucket, key, versionID string, attributes []*string) (*s3.GetObjectAttributesOutput, error) {
	input := s3.GetObjectAttributesInput{
		Bucket:           aws.String(bucket),
		Key:              aws.String(key),
		ObjectAttributes: attributes,
	}
	if versionID != "" {
		input.VersionId = aws.String(versionID)
	}
	return client.GetObjectAttributesWithContext(ctx, &input)
}

func copyObject(ctx context.Context, client *s3.S3, sourceBucket, sourceKey, sourceVersionID, destBucket, destKey string) (*s3.CopyObjectOutput, error) {
	return client.CopyObjectWithContext(ctx, &s3.CopyObjectInput{
		Bucket:     aws.String(destBucket),
		Key:        aws.String(destKey),
		CopySource: aws.String(sourceBucket + "/" + sourceKey + "?versionId=" + sourceVersionID),
	})
}

func copyObjectWithRetention(ctx context.Context, client *s3.S3, sourceBucket, sourceKey, sourceVersionID, destBucket, destKey, lockMode string, retainUntil *time.Time) (*s3.CopyObjectOutput, error) {
	return client.CopyObjectWithContext(ctx, &s3.CopyObjectInput{
		Bucket:                    aws.String(destBucket),
		Key:                       aws.String(destKey),
		CopySource:                aws.String(sourceBucket + "/" + sourceKey + "?versionId=" + sourceVersionID),
		ObjectLockMode:            aws.String(lockMode),
		ObjectLockRetainUntilDate: retainUntil,
	})
}

func copyObjectWithLegalHoldAndRetention(ctx context.Context, client *s3.S3, sourceBucket, sourceKey, sourceVersionID, destBucket, destKey, legalHoldStatus, lockMode string, retainUntil *time.Time) (*s3.CopyObjectOutput, error) {
	return client.CopyObjectWithContext(ctx, &s3.CopyObjectInput{
		Bucket:                    aws.String(destBucket),
		Key:                       aws.String(destKey),
		CopySource:                aws.String(sourceBucket + "/" + sourceKey + "?versionId=" + sourceVersionID),
		ObjectLockLegalHoldStatus: aws.String(legalHoldStatus),
		ObjectLockMode:            aws.String(lockMode),
		ObjectLockRetainUntilDate: retainUntil,
	})
}

func deleteObject(ctx context.Context, client *s3.S3, bucket, key, versionID string) error {
	input := s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}
	if versionID != "" {
		input.VersionId = aws.String(versionID)
	}
	_, err := client.DeleteObjectWithContext(ctx, &input)
	return err
}

func deleteObjectBypassGovernance(ctx context.Context, client *s3.S3, bucket, key, versionID string) error {
	input := s3.DeleteObjectInput{
		Bucket:                    aws.String(bucket),
		Key:                       aws.String(key),
		BypassGovernanceRetention: aws.Bool(true),
	}
	if versionID != "" {
		input.VersionId = aws.String(versionID)
	}
	_, err := client.DeleteObjectWithContext(ctx, &input)
	return err
}

func errorCode(err error) string {
	var awsErr awserr.Error
	if errors.As(err, &awsErr) {
		return awsErr.Code()
	}
	return ""
}

func statusCode(err error) int {
	var reqErr awserr.RequestFailure
	if errors.As(err, &reqErr) {
		return reqErr.StatusCode()
	}
	return 0
}

func requireS3Error(t *testing.T, err error, status int, code string) {
	require.Error(t, err)
	require.Equal(t, status, statusCode(err))
	require.Equal(t, code, errorCode(err))
}
