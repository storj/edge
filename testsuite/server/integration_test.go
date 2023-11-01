// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package server_test

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/minio/minio-go/v7"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"storj.io/common/errs2"
	"storj.io/common/fpath"
	"storj.io/common/memory"
	"storj.io/common/storj"
	"storj.io/common/testcontext"
	"storj.io/common/testrand"
	"storj.io/edge/internal/minioclient"
	"storj.io/edge/internal/register"
	"storj.io/edge/pkg/auth"
	"storj.io/edge/pkg/auth/badgerauth"
	"storj.io/edge/pkg/authclient"
	"storj.io/edge/pkg/server"
	"storj.io/edge/pkg/trustedip"
	"storj.io/private/cfgstruct"
	"storj.io/storj/private/testplanet"
	"storj.io/storj/satellite"
	"storj.io/storj/satellite/buckets"
	"storj.io/storj/satellite/nodeselection"
)

var counter int64

func TestUploadDownload(t *testing.T) {
	t.Parallel()

	testplanet.Run(t, testplanet.Config{
		SatelliteCount: 1, StorageNodeCount: 4, UplinkCount: 1,
		Reconfigure: testplanet.Reconfigure{
			Satellite: func(log *zap.Logger, index int, config *satellite.Config) {
				s := fmt.Sprintf(`40:annotated(annotated(country("PL"),annotation("%s","Poland")),annotation("%s","%s"))`,
					nodeselection.Location, nodeselection.AutoExcludeSubnet, nodeselection.AutoExcludeSubnetOFF)
				require.NoError(t, config.Placement.AddPlacementFromString(s))
			},
		},
	}, func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet) {
		access := planet.Uplinks[0].Access[planet.Satellites[0].ID()]

		// TODO: make address not hardcoded the address selection here may
		// conflict with some automatically bound address.
		authSvcAddr := fmt.Sprintf("127.0.0.1:1100%d", atomic.AddInt64(&counter, 1))
		authSvcAddrTLS := fmt.Sprintf("127.0.0.1:1100%d", atomic.AddInt64(&counter, 1))

		gwConfig := server.Config{}

		cfgstruct.Bind(&pflag.FlagSet{}, &gwConfig, cfgstruct.UseTestDefaults())

		gwConfig.Server.Address = "127.0.0.1:0"
		gwConfig.Auth.BaseURL = "http://" + authSvcAddr
		gwConfig.InsecureLogAll = true
		authClient := authclient.New(gwConfig.Auth)

		gateway, err := server.New(gwConfig, zaptest.NewLogger(t).Named("gateway"), trustedip.NewListTrustAll(), []string{}, authClient, 10)
		require.NoError(t, err)

		defer ctx.Check(gateway.Close)

		authConfig := auth.Config{
			Endpoint:          "http://" + gateway.Address(),
			AuthToken:         []string{"super-secret"},
			POSTSizeLimit:     4 * memory.KiB,
			AllowedSatellites: []string{planet.Satellites[0].NodeURL().String()},
			KVBackend:         "badger://",
			ListenAddr:        authSvcAddr,
			ListenAddrTLS:     authSvcAddrTLS,
			Node: badgerauth.Config{
				FirstStart:          true,
				ReplicationInterval: 5 * time.Second,
			},
		}

		auth, err := auth.New(ctx, zaptest.NewLogger(t).Named("auth"), authConfig, fpath.ApplicationDir("storj", "authservice"))
		require.NoError(t, err)

		// auth peer needs to be canceled to shut the servers down.
		cancelCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		ctx.Go(func() error {
			defer ctx.Check(auth.Close)
			return errs2.IgnoreCanceled(auth.Run(cancelCtx))
		})

		require.NoError(t, waitForAuthSvcStart(ctx, authClient, time.Second))

		serialized, err := access.Serialize()
		require.NoError(t, err)

		s3Credentials, err := register.Access(ctx, "http://"+authSvcAddr, serialized, false)
		require.NoError(t, err)

		client, err := minioclient.NewMinio(minioclient.Config{
			S3Gateway: gateway.Address(),
			Satellite: planet.Satellites[0].Addr(),
			AccessKey: s3Credentials.AccessKeyID,
			SecretKey: s3Credentials.SecretKey,
			APIKey:    planet.Uplinks[0].APIKey[planet.Satellites[0].ID()].Serialize(),
			NoSSL:     true,
		})
		require.NoError(t, err)

		ctx.Go(func() error {
			return gateway.Run(ctx)
		})

		require.NoError(t, waitForGatewayStart(ctx, client, 5*time.Second))

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
				Credentials:      credentials.NewStaticCredentials(s3Credentials.AccessKeyID, s3Credentials.SecretKey, ""),
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
			require.Equal(t, "us-east-1", location) // MinIO's SDK swaps empty location for "us-east-1"…

			require.NoError(t, planet.Uplinks[0].CreateBucket(ctx, planet.Satellites[0], "bucket-with-location-set"))

			_, err = planet.Satellites[0].DB.Buckets().UpdateBucket(ctx, buckets.Bucket{
				ProjectID: planet.Uplinks[0].Projects[0].ID,
				Name:      "bucket-with-location-set",
				Placement: storj.PlacementConstraint(40),
			})
			require.NoError(t, err)

			location, err = client.GetBucketLocation(ctx, "bucket-with-location-set")
			require.NoError(t, err)
			require.Equal(t, "Poland", location)
		}
	})
}

// waitForAuthSvcStart checks if authservice is ready using constant backoff.
func waitForAuthSvcStart(ctx context.Context, authClient *authclient.AuthClient, maxStartupWait time.Duration) error {
	for start := time.Now(); ; {
		_, err := authClient.GetHealthLive(ctx)
		if err == nil {
			return nil
		}

		// wait a bit before retrying to reduce load
		time.Sleep(50 * time.Millisecond)
		if time.Since(start) > maxStartupWait {
			return errs.New("exceeded maxStartupWait duration")
		}
	}
}

// waitForGatewayStart checks if Gateway-MT is ready using constant backoff.
func waitForGatewayStart(ctx context.Context, client minioclient.Client, maxStartupWait time.Duration) error {
	for start := time.Now(); ; {
		_, err := client.ListBuckets(ctx)
		if err == nil {
			return nil
		}

		// wait a bit before retrying to reduce load
		time.Sleep(50 * time.Millisecond)
		if time.Since(start) > maxStartupWait {
			return errs.New("exceeded maxStartupWait duration")
		}
	}
}
