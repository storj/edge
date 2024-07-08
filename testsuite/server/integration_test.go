// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package server_test

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
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
	}, func(ctx *testcontext.Context, planet *testplanet.Planet, gateway *server.Peer, creds register.Credentials) {
		sess, err := session.NewSession(&aws.Config{
			Region:           aws.String("global"),
			Credentials:      credentials.NewStaticCredentials(creds.AccessKeyID, creds.SecretKey, ""),
			Endpoint:         aws.String("http://" + gateway.Address()),
			S3ForcePathStyle: aws.Bool(true),
		})
		require.NoError(t, err)

		client := s3.New(sess)

		_, err = client.ListObjects(&s3.ListObjectsInput{Bucket: aws.String("watchedbucket")})
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
	}, nil, func(ctx *testcontext.Context, planet *testplanet.Planet, gateway *server.Peer, creds register.Credentials) {
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
			newSession, err := session.NewSession(&aws.Config{
				Credentials:      credentials.NewStaticCredentials(creds.AccessKeyID, creds.SecretKey, ""),
				Endpoint:         aws.String("http://" + gateway.Address()),
				Region:           aws.String("us-east-1"),
				S3ForcePathStyle: aws.Bool(true),
			})
			require.NoError(t, err)
			s3Client := s3.New(newSession)

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
	}, nil, func(ctx *testcontext.Context, planet *testplanet.Planet, gateway *server.Peer, creds register.Credentials) {
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
	test func(ctx *testcontext.Context, planet *testplanet.Planet, gateway *server.Peer, creds register.Credentials),
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

		test(ctx, planet, gateway, creds)
	})
}
