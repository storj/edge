// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package server_test

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
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
	"storj.io/edge/pkg/accesslogs"
	"storj.io/edge/pkg/auth"
	"storj.io/edge/pkg/auth/spannerauth"
	"storj.io/edge/pkg/auth/spannerauth/spannerauthtest"
	"storj.io/edge/pkg/authclient"
	"storj.io/edge/pkg/server"
	"storj.io/edge/pkg/server/middleware"
	"storj.io/edge/pkg/trustedip"
	"storj.io/minio/pkg/bucket/versioning"
	"storj.io/storj/private/testplanet"
	"storj.io/storj/satellite"
	"storj.io/storj/satellite/buckets"
	"storj.io/uplink"
)

const (
	lockModeCompliance = s3.ObjectLockModeCompliance
	lockModeGovernance = s3.ObjectLockModeGovernance
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
				config.Metainfo.ProjectLimits.MaxBuckets = 20
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

		objKey1 := "testobject1"

		t.Run("api key version disallows object lock", func(t *testing.T) {
			userCtx, err := satellite.UserContext(ctx, ownerID)
			require.NoError(t, err)

			_, apiKey, err := satellite.API.Console.Service.CreateAPIKey(userCtx, projectID, "restricted", macaroon.APIKeyVersionMin)
			require.NoError(t, err)

			creds := registerAccess(ctx, t, encAccess, apiKey, satellite.URL(), auth.Address())
			client := createS3Client(t, gateway.Address(), creds.AccessKeyID, creds.SecretKey)

			requireS3Error(t, createBucket(ctx, client, testrand.BucketName(), true, true), http.StatusForbidden, "AccessDenied")
		})

		t.Run("allow get retention disallow put retention", func(t *testing.T) {
			restrictedApiKey, err := apiKey.Restrict(macaroon.Caveat{
				DisallowPutRetention: true,
			})
			require.NoError(t, err)

			restrictedCreds := registerAccess(ctx, t, encAccess, restrictedApiKey, satellite.URL(), auth.Address())
			restrictedClient := createS3Client(t, gateway.Address(), restrictedCreds.AccessKeyID, restrictedCreds.SecretKey)

			bucket := testrand.BucketName()

			requireS3Error(t, createBucket(ctx, restrictedClient, bucket, true, true), http.StatusForbidden, "AccessDenied")

			require.NoError(t, createBucket(ctx, allowedClient, bucket, true, true))

			retainUntil := time.Now().Add(10 * time.Minute)

			_, err = putObjectWithRetention(ctx, restrictedClient, bucket, objKey1, lockModeCompliance, retainUntil)
			requireS3Error(t, err, http.StatusForbidden, "AccessDenied")

			putResp, err := putObjectWithRetention(ctx, allowedClient, bucket, objKey1, lockModeCompliance, retainUntil)
			require.NoError(t, err)

			retResp, err := getObjectRetention(ctx, restrictedClient, bucket, objKey1, *putResp.VersionId)
			require.NoError(t, err)
			require.Equal(t, lockModeCompliance, *retResp.Retention.Mode)
			require.WithinDuration(t, retainUntil, *retResp.Retention.RetainUntilDate, time.Minute)
		})

		t.Run("allow put retention implicitly allows get retention", func(t *testing.T) {
			restrictedApiKey, err := apiKey.Restrict(macaroon.Caveat{
				DisallowGetRetention: true,
			})
			require.NoError(t, err)

			restrictedCreds := registerAccess(ctx, t, encAccess, restrictedApiKey, satellite.URL(), auth.Address())
			restrictedClient := createS3Client(t, gateway.Address(), restrictedCreds.AccessKeyID, restrictedCreds.SecretKey)

			bucket := testrand.BucketName()

			require.NoError(t, createBucket(ctx, restrictedClient, bucket, true, true))

			retainUntil := time.Now().Add(10 * time.Minute)

			putResp, err := putObjectWithRetention(ctx, restrictedClient, bucket, objKey1, lockModeCompliance, retainUntil)
			require.NoError(t, err)

			retResp, err := getObjectRetention(ctx, restrictedClient, bucket, objKey1, *putResp.VersionId)
			require.NoError(t, err)
			require.Equal(t, lockModeCompliance, *retResp.Retention.Mode)
			require.WithinDuration(t, retainUntil, *retResp.Retention.RetainUntilDate, time.Minute)
		})

		// TODO: expand test of legal hold and governance permissions.
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
				config.Metainfo.ProjectLimits.MaxBuckets = 20
			},
			Uplink: func(log *zap.Logger, index int, config *testplanet.UplinkConfig) {
				config.APIKeyVersion = macaroon.APIKeyVersionObjectLock
			},
		},
	}, nil, func(ctx *testcontext.Context, planet *testplanet.Planet, gateway *server.Peer, auth *auth.Peer, creds register.Credentials) {
		client := createS3Client(t, gateway.Address(), creds.AccessKeyID, creds.SecretKey)

		objKey1, objKey2, objKey3 := "testobject1", "testobject2", "testobject3"

		// TODO: expand this test case when PutObjectLockConfiguration is supported.
		t.Run("enable and disable object lock on bucket", func(t *testing.T) {
			bucket := testrand.BucketName()
			require.NoError(t, createBucket(ctx, client, bucket, true, false))

			_, err := getObjectLockConfiguration(ctx, client, bucket)
			requireS3Error(t, err, http.StatusNotFound, "ObjectLockConfigurationNotFoundError")

			_, err = putObjectLockConfiguration(ctx, client, bucket, "Enabled", nil)
			requireS3Error(t, err, http.StatusNotImplemented, "NotImplemented")

			_, err = putObjectLockConfiguration(ctx, client, bucket, "Disabled", nil)
			requireS3Error(t, err, http.StatusNotImplemented, "NotImplemented")

			bucket2 := testrand.BucketName()
			require.NoError(t, createBucket(ctx, client, bucket2, true, true))

			resp, err := getObjectLockConfiguration(ctx, client, bucket2)
			require.NoError(t, err)
			require.Equal(t, "Enabled", *resp.ObjectLockConfiguration.ObjectLockEnabled)
		})

		t.Run("put object with lock not allowed on unversioned bucket", func(t *testing.T) {
			bucket := testrand.BucketName()
			require.NoError(t, createBucket(ctx, client, bucket, false, false))

			_, err := putObjectWithRetention(ctx, client, bucket, objKey1, lockModeCompliance, time.Now().Add(5*time.Minute))
			requireS3Error(t, err, http.StatusBadRequest, "InvalidRequest")
		})

		t.Run("put object with lock enables versioning implicitly", func(t *testing.T) {
			bucket := testrand.BucketName()
			require.NoError(t, createBucket(ctx, client, bucket, false, true))

			resp, err := putObjectWithRetention(ctx, client, bucket, objKey1, lockModeCompliance, time.Now().Add(5*time.Minute))
			require.NoError(t, err)
			require.NotEmpty(t, resp.VersionId)
		})

		t.Run("put object with lock not allowed when bucket lock disabled", func(t *testing.T) {
			bucket := testrand.BucketName()
			require.NoError(t, createBucket(ctx, client, bucket, true, false))

			_, err := putObjectWithRetention(ctx, client, bucket, objKey1, lockModeCompliance, time.Now().Add(5*time.Minute))
			requireS3Error(t, err, http.StatusBadRequest, "InvalidRequest")
		})

		t.Run("suspending versioning is not allowed when object lock enabled on bucket", func(t *testing.T) {
			bucket := testrand.BucketName()
			require.NoError(t, createBucket(ctx, client, bucket, true, true))

			_, err := client.PutBucketVersioning(&s3.PutBucketVersioningInput{
				Bucket: aws.String(bucket),
				VersioningConfiguration: &s3.VersioningConfiguration{
					Status: aws.String(s3.BucketVersioningStatusSuspended),
				},
			})
			// TODO: AccessDenied here doesn't seem like the right error code.
			requireS3Error(t, err, http.StatusForbidden, "AccessDenied")
		})

		t.Run("get object retention error handling", func(t *testing.T) {
			bucket := testrand.BucketName()
			require.NoError(t, createBucket(ctx, client, bucket, true, false))

			_, err := putObject(ctx, client, bucket, objKey1, nil)
			require.NoError(t, err)

			_, err = getObjectRetention(ctx, client, bucket, objKey1, "")
			requireS3Error(t, err, http.StatusBadRequest, "InvalidRequest")
			// Note: S3 returns 400 InvalidRequest for GetObjectRetention when the bucket has no lock configuration.
			// If the bucket does have lock configuration it instead returns 404 NoSuchObjectLockConfiguration.

			bucket2 := testrand.BucketName()
			require.NoError(t, createBucket(ctx, client, bucket2, true, true))

			_, err = putObject(ctx, client, bucket2, objKey1, nil)
			require.NoError(t, err)

			_, err = getObjectRetention(ctx, client, bucket2, objKey1, "")
			requireS3Error(t, err, http.StatusNotFound, "NoSuchObjectLockConfiguration")

			retainUntil := time.Now().Add(10 * time.Minute)

			_, err = putObjectWithRetention(ctx, client, bucket2, objKey2, lockModeCompliance, retainUntil)
			require.NoError(t, err)

			require.NoError(t, deleteObject(ctx, client, bucket2, objKey2, ""))

			_, err = getObjectRetention(ctx, client, bucket2, objKey2, "")
			requireS3Error(t, err, http.StatusMethodNotAllowed, "MethodNotAllowed")
		})

		t.Run("invalid retention mode", func(t *testing.T) {
			bucket := testrand.BucketName()
			require.NoError(t, createBucket(ctx, client, bucket, true, true))

			retainUntil := time.Now().Add(10 * time.Minute)

			_, err := putObjectWithRetention(ctx, client, bucket, objKey1, lockModeGovernance, retainUntil)
			require.Error(t, err)
			// TODO: fix unmapped error "invalid retention mode 0, expected 1 (compliance)"
			// TODO: this governance test can be removed once governance mode is supported
			// requireErrorWithCode(t, err, "InvalidRequest")

			_, err = putObjectWithRetention(ctx, client, bucket, objKey1, "invalidmode", retainUntil)
			requireS3Error(t, err, http.StatusBadRequest, "InvalidRequest")

			_, err = putObjectMultipartWithRetention(ctx, client, bucket, objKey2, "invalidmode", retainUntil)
			requireS3Error(t, err, http.StatusBadRequest, "InvalidRequest")
		})

		t.Run("legal hold", func(t *testing.T) {
			bucket := testrand.BucketName()
			require.NoError(t, createBucket(ctx, client, bucket, true, true))

			_, err := putObjectWithLegalHold(ctx, client, bucket, objKey1, "ON")
			require.NoError(t, err)

			_, err = putObject(ctx, client, bucket, objKey1, nil)
			require.NoError(t, err)

			_, err = putObjectLegalHold(ctx, client, bucket, objKey1, "ON")
			require.NoError(t, err)

			response, err := getObjectLegalHold(ctx, client, bucket, objKey1, "")
			require.NoError(t, err)
			require.NotNil(t, response)
			require.Equal(t, "ON", *response.LegalHold.Status)

			_, err = putObjectLegalHold(ctx, client, bucket, objKey1, "OFF")
			require.NoError(t, err)

			response, err = getObjectLegalHold(ctx, client, bucket, objKey1, "")
			require.NoError(t, err)
			require.NotNil(t, response)
			require.Equal(t, "OFF", *response.LegalHold.Status)

			_, err = putObjectLegalHold(ctx, client, bucket, objKey1, "INVALID")
			requireS3Error(t, err, http.StatusBadRequest, "MalformedXML")
		})

		t.Run("extending retention time allowed but shortening is not", func(t *testing.T) {
			bucket := testrand.BucketName()
			require.NoError(t, createBucket(ctx, client, bucket, true, true))

			retainUntil := time.Now().Add(10 * time.Minute)

			_, err := putObjectWithRetention(ctx, client, bucket, objKey1, lockModeCompliance, retainUntil)
			require.NoError(t, err)

			extendedRetainUntil := retainUntil.Add(10 * time.Minute)

			_, err = putObjectRetention(ctx, client, bucket, "doesntexist", lockModeCompliance, extendedRetainUntil)
			requireS3Error(t, err, http.StatusNotFound, "NoSuchKey")

			_, err = putObjectRetention(ctx, client, bucket, objKey1, lockModeCompliance, extendedRetainUntil)
			require.NoError(t, err)

			objInfo, err := getObject(ctx, client, bucket, objKey1, "")
			require.NoError(t, err)
			require.WithinDuration(t, extendedRetainUntil, *objInfo.ObjectLockRetainUntilDate, time.Minute)

			_, err = putObjectRetention(ctx, client, bucket, objKey1, lockModeCompliance, extendedRetainUntil.Add(-1*time.Hour))
			require.Error(t, err)
			// TODO: MalformedXML is returned here instead of "InvalidRequest" or "InvalidArgument"
			// S3: HTTP 400: "InvalidArgument: The retain until date must be in the future!"
			requireS3Error(t, err, http.StatusBadRequest, "MalformedXML")

			_, err = putObjectMultipartWithRetention(ctx, client, bucket, objKey2, lockModeCompliance, extendedRetainUntil.Add(-1*time.Hour))
			requireS3Error(t, err, http.StatusBadRequest, "InvalidRequest")
		})

		t.Run("object lock settings returned in object info", func(t *testing.T) {
			bucket := testrand.BucketName()
			require.NoError(t, createBucket(ctx, client, bucket, true, true))

			retainUntil := time.Now().Add(10 * time.Minute)

			putResp, err := putObjectWithRetention(ctx, client, bucket, objKey1, lockModeCompliance, retainUntil)
			require.NoError(t, err)

			objInfo, err := getObject(ctx, client, bucket, objKey1, "")
			require.NoError(t, err)
			require.Equal(t, putResp.VersionId, objInfo.VersionId)
			require.Equal(t, lockModeCompliance, *objInfo.ObjectLockMode)
			require.WithinDuration(t, retainUntil, *objInfo.ObjectLockRetainUntilDate, time.Minute)

			_, err = getObjectRetention(ctx, client, bucket, "nonexistent", "")
			requireS3Error(t, err, http.StatusNotFound, "NoSuchKey")

			retResp, err := getObjectRetention(ctx, client, bucket, objKey1, *putResp.VersionId)
			require.NoError(t, err)
			require.Equal(t, lockModeCompliance, *retResp.Retention.Mode)
			require.WithinDuration(t, retainUntil, *retResp.Retention.RetainUntilDate, time.Minute)
		})

		t.Run("delete locked object version not allowed", func(t *testing.T) {
			bucket := testrand.BucketName()
			require.NoError(t, createBucket(ctx, client, bucket, true, true))

			retainUntil := time.Now().Add(10 * time.Minute)

			putResp, err := putObjectWithRetention(ctx, client, bucket, objKey1, lockModeCompliance, retainUntil)
			require.NoError(t, err)

			requireS3Error(t, deleteObject(ctx, client, bucket, objKey1, *putResp.VersionId), http.StatusForbidden, "AccessDenied")

			mpResp, err := putObjectMultipartWithRetention(ctx, client, bucket, objKey2, lockModeCompliance, retainUntil)
			require.NoError(t, err)

			requireS3Error(t, deleteObject(ctx, client, bucket, objKey2, *mpResp.VersionId), http.StatusForbidden, "AccessDenied")
		})

		t.Run("copy object", func(t *testing.T) {
			bucket := testrand.BucketName()
			require.NoError(t, createBucket(ctx, client, bucket, true, true))

			noLockBucket := testrand.BucketName()
			require.NoError(t, createBucket(ctx, client, noLockBucket, true, false))

			retainUntil := time.Now().Add(10 * time.Minute)

			putResp, err := putObjectWithRetention(ctx, client, bucket, objKey1, lockModeCompliance, retainUntil)
			require.NoError(t, err)

			_, err = copyObjectWithRetention(ctx, client, bucket, objKey1, *putResp.VersionId, noLockBucket, objKey2, lockModeCompliance, &retainUntil)
			requireS3Error(t, err, http.StatusBadRequest, "InvalidRequest")

			copyResp, err := copyObject(ctx, client, bucket, objKey1, *putResp.VersionId, bucket, objKey2)
			require.NoError(t, err)

			_, err = getObjectRetention(ctx, client, bucket, objKey2, *copyResp.VersionId)
			requireS3Error(t, err, http.StatusNotFound, "NoSuchObjectLockConfiguration")

			objInfo, err := getObject(ctx, client, bucket, objKey2, "")
			require.NoError(t, err)
			require.Nil(t, objInfo.ObjectLockMode)
			require.Nil(t, objInfo.ObjectLockRetainUntilDate)

			require.NoError(t, deleteObject(ctx, client, bucket, objKey2, *copyResp.VersionId))

			copyResp, err = copyObjectWithRetention(ctx, client, bucket, objKey1, *putResp.VersionId, bucket, objKey3, lockModeCompliance, &retainUntil)
			require.NoError(t, err)

			retResp, err := getObjectRetention(ctx, client, bucket, objKey3, *copyResp.VersionId)
			require.NoError(t, err)
			require.Equal(t, lockModeCompliance, *retResp.Retention.Mode)
			require.WithinDuration(t, retainUntil, *retResp.Retention.RetainUntilDate, time.Minute)

			requireS3Error(t, deleteObject(ctx, client, bucket, objKey3, *copyResp.VersionId), http.StatusForbidden, "AccessDenied")
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
		require.NoError(t, planet.Uplinks[0].CreateBucket(ctx, planet.Satellites[0], "watchedbucket"))
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
				Storage:    accesslogs.NewStorjStorage(logsAccess),
				Prefix:     "logs/",
			},
		})
		require.NoError(t, err)
		gwConfig.ServerAccessLogging = accessLogConfig
	}, func(ctx *testcontext.Context, planet *testplanet.Planet, gateway *server.Peer, auth *auth.Peer, creds register.Credentials) {
		client := createS3Client(t, gateway.Address(), creds.AccessKeyID, creds.SecretKey)

		_, err := client.ListObjects(&s3.ListObjectsInput{Bucket: aws.String("watchedbucket")})
		require.NoError(t, err)

		testFilePath := ctx.File("random1.dat")
		require.NoError(t, os.WriteFile(testFilePath, testrand.Bytes(123), 0600))

		testFile, err := os.Open(testFilePath)
		require.NoError(t, err)

		_, err = client.PutObject(&s3.PutObjectInput{
			Bucket: aws.String("watchedbucket"),
			Key:    aws.String("testfile/random1.dat"),
			Body:   testFile,
		})
		require.NoError(t, err)

		_, err = client.GetObject(&s3.GetObjectInput{
			Bucket: aws.String("watchedbucket"),
			Key:    aws.String("testfile/random1.dat"),
		})
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
		require.Len(t, logs, 3)
		require.Contains(t, logs[0], "GET /watchedbucket HTTP/1.1")
		require.Contains(t, logs[1], "PUT /watchedbucket/testfile/random1.dat HTTP/1.1")
		require.Contains(t, logs[2], "GET /watchedbucket/testfile/random1.dat HTTP/1.1")
		require.Contains(t, logs[2], "123")
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

func putObjectLegalHold(ctx context.Context, client *s3.S3, bucket, key, status string) (*s3.PutObjectLegalHoldOutput, error) {
	return client.PutObjectLegalHoldWithContext(ctx, &s3.PutObjectLegalHoldInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		LegalHold: &s3.ObjectLockLegalHold{
			Status: aws.String(status),
		},
	})
}

func getObjectLegalHold(ctx context.Context, client *s3.S3, bucket, key, versionID string) (*s3.GetObjectLegalHoldOutput, error) {
	return client.GetObjectLegalHoldWithContext(ctx, &s3.GetObjectLegalHoldInput{
		Bucket:    aws.String(bucket),
		Key:       aws.String(key),
		VersionId: aws.String(versionID),
	})
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

func putObjectWithLegalHold(ctx context.Context, client *s3.S3, bucket, key, legalHoldStatus string) (*s3.PutObjectOutput, error) {
	return client.PutObjectWithContext(ctx, &s3.PutObjectInput{
		Bucket:                    aws.String(bucket),
		Key:                       aws.String(key),
		ObjectLockLegalHoldStatus: aws.String(legalHoldStatus),
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

func putObjectRetention(ctx context.Context, client *s3.S3, bucket, key, lockMode string, retainUntil time.Time) (*s3.PutObjectRetentionOutput, error) {
	return client.PutObjectRetentionWithContext(ctx, &s3.PutObjectRetentionInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Retention: &s3.ObjectLockRetention{
			Mode:            aws.String(lockMode),
			RetainUntilDate: aws.Time(retainUntil),
		},
	})
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
