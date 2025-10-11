// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package mcpserver_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/cfgstruct"
	"storj.io/common/errs2"
	"storj.io/common/fpath"
	"storj.io/common/testcontext"
	"storj.io/common/testrand"
	"storj.io/edge/pkg/auth"
	"storj.io/edge/pkg/auth/spannerauth"
	"storj.io/edge/pkg/auth/spannerauth/spannerauthtest"
	"storj.io/edge/pkg/authclient"
	mcpclient "storj.io/edge/pkg/mcp-client"
	mcpserver "storj.io/edge/pkg/mcp-server"
	"storj.io/storj/private/testplanet"
)

func TestBucketOperations(t *testing.T) {
	runTest(t, testplanet.Config{
		SatelliteCount:   1,
		StorageNodeCount: 0,
		UplinkCount:      1,
	}, nil, func(ctx *testcontext.Context, t *testing.T, planet *testplanet.Planet, server *mcpserver.Peer, bearerToken string) {
		client, err := mcpclient.New("http://"+server.Address()+"/mcp/jsonrpc", bearerToken)
		require.NoError(t, err)

		bucket := testrand.BucketName()

		// TODO: add cursor and limit tests for ListBuckets.
		listResp, err := client.ListBuckets(ctx, mcpclient.ListBucketsRequest{})
		require.NoError(t, err)
		require.Empty(t, listResp.Buckets)

		createResp, err := client.CreateBucket(ctx, mcpclient.CreateBucketRequest{
			Bucket: bucket,
		})
		require.NoError(t, err)
		require.Equal(t, bucket, createResp.Bucket)
		require.Equal(t, "created", createResp.Status)

		_, err = client.CreateBucket(ctx, mcpclient.CreateBucketRequest{
			Bucket: bucket,
		})
		require.Error(t, err)

		listResp, err = client.ListBuckets(ctx, mcpclient.ListBucketsRequest{})
		require.NoError(t, err)

		require.Len(t, listResp.Buckets, 1)
		require.Equal(t, bucket, listResp.Buckets[0].Name)
		require.NotZero(t, listResp.Buckets[0].Created)

		statResp, err := client.StatBucket(ctx, mcpclient.StatBucketRequest{
			Bucket: bucket,
		})
		require.NoError(t, err)
		require.Equal(t, bucket, statResp.Name)
		require.NotZero(t, statResp.Created)

		deleteResp, err := client.DeleteBucket(ctx, mcpclient.DeleteBucketRequest{
			Bucket: bucket,
		})
		require.NoError(t, err)
		require.Equal(t, bucket, deleteResp.Bucket)
		require.Equal(t, "deleted", deleteResp.Status)
	})
}

func TestObjectOperations(t *testing.T) {
	runTest(t, testplanet.Config{
		SatelliteCount:   1,
		StorageNodeCount: 0,
		UplinkCount:      1,
	}, nil, func(ctx *testcontext.Context, t *testing.T, planet *testplanet.Planet, server *mcpserver.Peer, bearerToken string) {
		client, err := mcpclient.New("http://"+server.Address()+"/mcp/jsonrpc", bearerToken)
		require.NoError(t, err)

		// testrand.Path() isn't used for the object key because it produces invalid UTF-8 strings,
		// which are mangled by the JSON marshaller.
		bucket, key := testrand.BucketName(), string(testrand.RandAlphaNumeric(8))

		_, err = client.CreateBucket(ctx, mcpclient.CreateBucketRequest{
			Bucket: bucket,
		})
		require.NoError(t, err)

		_, err = client.ListObjects(ctx, mcpclient.ListObjectsRequest{})
		require.Error(t, err)

		// TODO: add cursor and limit tests for ListObjects.
		listResp, err := client.ListObjects(ctx, mcpclient.ListObjectsRequest{
			Bucket: bucket,
		})
		require.NoError(t, err)
		require.Empty(t, listResp.Objects)

		uploadResp, err := client.UploadObject(ctx, mcpclient.UploadObjectRequest{
			Bucket: bucket,
			Key:    key,
			Data:   base64.StdEncoding.EncodeToString([]byte("test data")),
		})
		require.NoError(t, err)
		require.Equal(t, bucket, uploadResp.Bucket)
		require.Equal(t, key, uploadResp.Key)
		require.Equal(t, "uploaded", uploadResp.Status)

		listResp, err = client.ListObjects(ctx, mcpclient.ListObjectsRequest{
			Bucket: bucket,
		})
		require.NoError(t, err)
		require.Len(t, listResp.Objects, 1)
		require.Equal(t, key, listResp.Objects[0].Key)
		require.Equal(t, int64(9), listResp.Objects[0].Size)
		require.NotZero(t, listResp.Objects[0].Modified)

		destBucket, destKey := testrand.BucketName(), key+"-copy"

		_, err = client.CreateBucket(ctx, mcpclient.CreateBucketRequest{
			Bucket: destBucket,
		})
		require.NoError(t, err)

		copyResp, err := client.CopyObject(ctx, mcpclient.CopyObjectRequest{
			SrcBucket:  bucket,
			SrcKey:     key,
			DestBucket: destBucket,
			DestKey:    destKey,
		})
		require.NoError(t, err)
		require.Equal(t, bucket, copyResp.SrcBucket)
		require.Equal(t, key, copyResp.SrcKey)
		require.Equal(t, destBucket, copyResp.DestBucket)
		require.Equal(t, destKey, copyResp.DestKey)
		require.Equal(t, "copied", copyResp.Status)

		listResp, err = client.ListObjects(ctx, mcpclient.ListObjectsRequest{
			Bucket: destBucket,
		})
		require.NoError(t, err)
		require.Len(t, listResp.Objects, 1)

		deleteObjResp, err := client.DeleteObject(ctx, mcpclient.DeleteObjectRequest{
			Bucket: bucket,
			Key:    key,
		})
		require.NoError(t, err)
		require.Equal(t, bucket, deleteObjResp.Bucket)
		require.Equal(t, key, deleteObjResp.Key)
		require.Equal(t, "deleted", deleteObjResp.Status)
	})
}

func TestMultipartUpload(t *testing.T) {
	runTest(t, testplanet.Config{
		SatelliteCount:   1,
		StorageNodeCount: 0,
		UplinkCount:      1,
	}, nil, func(ctx *testcontext.Context, t *testing.T, planet *testplanet.Planet, server *mcpserver.Peer, bearerToken string) {
		client, err := mcpclient.New("http://"+server.Address()+"/mcp/jsonrpc", bearerToken)
		require.NoError(t, err)

		// testrand.Path() isn't used for the object key because it produces invalid UTF-8 strings,
		// which are mangled by the JSON marshaller.
		bucket, key := testrand.BucketName(), string(testrand.RandAlphaNumeric(8))

		_, err = client.CreateBucket(ctx, mcpclient.CreateBucketRequest{
			Bucket: bucket,
		})
		require.NoError(t, err)

		uploadResp, err := client.BeginUpload(ctx, mcpclient.BeginUploadRequest{
			Bucket: bucket,
			Key:    key,
		})
		require.NoError(t, err)
		require.Equal(t, bucket, uploadResp.Bucket)
		require.Equal(t, key, uploadResp.Key)
		require.NotEmpty(t, uploadResp.UploadID)
		require.Equal(t, "started", uploadResp.Status)

		listUploadsResp, err := client.ListUploads(ctx, mcpclient.ListUploadsRequest{
			Bucket: bucket,
		})
		require.NoError(t, err)
		require.Len(t, listUploadsResp.Uploads, 1)
		require.Equal(t, uploadResp.UploadID, listUploadsResp.Uploads[0].UploadID)
		require.Equal(t, key, listUploadsResp.Uploads[0].Key)
		require.NotZero(t, listUploadsResp.Uploads[0].Created)

		partResp, err := client.UploadPart(ctx, mcpclient.UploadPartRequest{
			Bucket:     bucket,
			Key:        key,
			UploadID:   uploadResp.UploadID,
			PartNumber: 1,
			Data:       base64.StdEncoding.EncodeToString([]byte("test data")),
		})
		require.NoError(t, err)
		require.Equal(t, bucket, partResp.Bucket)
		require.Equal(t, key, partResp.Key)
		require.Equal(t, uploadResp.UploadID, partResp.UploadID)
		require.Equal(t, 1, partResp.PartNumber)
		require.Equal(t, 9, partResp.Size)
		require.Equal(t, "uploaded", partResp.Status)

		listPartsResp, err := client.ListUploadParts(ctx, mcpclient.ListUploadPartsRequest{
			Bucket:   bucket,
			Key:      key,
			UploadID: uploadResp.UploadID,
		})
		require.NoError(t, err)
		require.Equal(t, bucket, listPartsResp.Bucket)
		require.Equal(t, key, listPartsResp.Key)
		require.Equal(t, uploadResp.UploadID, listPartsResp.UploadID)
		require.Equal(t, 1, listPartsResp.Count)
		require.Len(t, listPartsResp.Parts, 1)
		require.Equal(t, uint32(1), listPartsResp.Parts[0].PartNumber)
		require.Equal(t, int64(9), listPartsResp.Parts[0].Size)
		require.NotZero(t, listPartsResp.Parts[0].Modified)
		// TODO: fix etag response.
		// require.NotEmpty(t, listPartsResp.Parts[0].ETag)

		commitResp, err := client.CommitUpload(ctx, mcpclient.CommitUploadRequest{
			Bucket:   bucket,
			Key:      key,
			UploadID: uploadResp.UploadID,
		})
		require.NoError(t, err)
		require.Equal(t, bucket, commitResp.Bucket)
		require.Equal(t, key, commitResp.Key)
		require.Equal(t, uploadResp.UploadID, commitResp.UploadID)
		require.Equal(t, int64(9), commitResp.Size)
		require.NotZero(t, commitResp.Created)
		require.Equal(t, "completed", commitResp.Status)

		listResp, err := client.ListObjects(ctx, mcpclient.ListObjectsRequest{
			Bucket: bucket,
		})
		require.NoError(t, err)
		require.Len(t, listResp.Objects, 1)
		require.Equal(t, key, listResp.Objects[0].Key)
		require.Equal(t, int64(9), listResp.Objects[0].Size)
		require.NotZero(t, listResp.Objects[0].Modified)
	})
}

func TestShareURL(t *testing.T) {
	testLinksharingURL := "https://linksharing.local"

	runTest(t, testplanet.Config{
		SatelliteCount:   1,
		StorageNodeCount: 0,
		UplinkCount:      1,
	}, func(ctx *testcontext.Context, planet *testplanet.Planet, mcpConfig *mcpserver.Config) {
		mcpConfig.LinkSharingURL = testLinksharingURL
	}, func(ctx *testcontext.Context, t *testing.T, planet *testplanet.Planet, server *mcpserver.Peer, bearerToken string) {
		expires := time.Now().Add(24 * time.Hour).Format(time.RFC3339)

		for _, tc := range []struct {
			name, bucket, key, expires                    string
			allowListing, expectedIsPrefix, expectedError bool
		}{
			{
				name:   "success",
				bucket: "testbucket",
				key:    "test/foo.txt",
			},
			{
				name:    "success with expiration",
				bucket:  "testbucket",
				key:     "test/bar.txt",
				expires: expires,
			},
			{
				name:          "missing bucket",
				key:           "test/foo.txt",
				expectedError: true,
			},
			{
				name:          "missing key",
				bucket:        "testbucket",
				expectedError: true,
			},
			{
				name:          "invalid expires format",
				bucket:        "testbucket",
				key:           "test/foo.txt",
				expires:       "invalid-time-format",
				expectedError: true,
			},
			{
				name:             "share prefix",
				bucket:           "testbucket",
				key:              "test/",
				allowListing:     true,
				expectedIsPrefix: true,
			},
			{
				name:             "share prefix list not allowed",
				bucket:           "testbucket",
				key:              "test/",
				expectedIsPrefix: true,
				expectedError:    false,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				client, err := mcpclient.New("http://"+server.Address()+"/mcp/jsonrpc", bearerToken)
				require.NoError(t, err)

				resp, err := client.ShareURL(ctx, mcpclient.ShareURLRequest{
					Bucket:       tc.bucket,
					Key:          tc.key,
					Expires:      tc.expires,
					AllowListing: tc.allowListing,
				})
				if tc.expectedError {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)

				require.Equal(t, tc.bucket, resp.Bucket)
				require.Equal(t, tc.key, resp.Key)
				require.Equal(t, tc.expectedIsPrefix, resp.IsPrefix)
				require.Equal(t, tc.allowListing, resp.AllowListing)
				require.Contains(t, resp.ShareURL, testLinksharingURL)
			})
		}
	})
}

func runTest(
	t *testing.T,
	planetConfig testplanet.Config,
	prepare func(ctx *testcontext.Context, planet *testplanet.Planet, mcpConfig *mcpserver.Config),
	test func(ctx *testcontext.Context, t *testing.T, planet *testplanet.Planet, gateway *mcpserver.Peer, bearerToken string),
) {
	testplanet.Run(t, planetConfig, func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet) {
		var mcpConfig mcpserver.Config
		cfgstruct.Bind(&pflag.FlagSet{}, &mcpConfig, cfgstruct.UseTestDefaults())

		var authConfig auth.Config
		cfgstruct.Bind(&pflag.FlagSet{}, &authConfig, cfgstruct.UseTestDefaults())

		if prepare != nil {
			prepare(ctx, planet, &mcpConfig)
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
		authConfig.RetrieveProjectInfo = true

		auth, err := auth.New(ctx, zaptest.NewLogger(t).Named("auth"), authConfig, fpath.ApplicationDir("storj", "authservice"))
		require.NoError(t, err)

		// auth peer needs to be canceled to shut the servers down.
		cancelCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		ctx.Go(func() error {
			defer ctx.Check(auth.Close)
			return errs2.IgnoreCanceled(auth.Run(cancelCtx))
		})

		mcpConfig.Address = "127.0.0.1:0"
		mcpConfig.Auth = authclient.Config{
			BaseURL: "http://" + auth.Address(),
			Token:   "super-secret",
		}
		mcpConfig.LinkSharingURL = "https://linksharing.local"

		server, err := mcpserver.New(zaptest.NewLogger(t).Named("mcpserver"), mcpConfig)
		require.NoError(t, err)

		ctx.Go(func() error {
			return server.Run(ctx)
		})

		defer ctx.Check(server.Close)

		access := planet.Uplinks[0].Access[planet.Satellites[0].ID()]
		serializedAccess, err := access.Serialize()
		require.NoError(t, err)

		reqBody, err := json.Marshal(struct {
			AccessGrant string `json:"access_grant"`
		}{
			AccessGrant: serializedAccess,
		})
		require.NoError(t, err)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+server.Address()+"/mcp/register", bytes.NewReader(reqBody))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)

		var registerData struct {
			BearerToken string `json:"bearer_token"`
		}

		require.NoError(t, json.NewDecoder(resp.Body).Decode(&registerData))

		require.NoError(t, resp.Body.Close())

		test(ctx, t, planet, server, registerData.BearerToken)
	})
}
