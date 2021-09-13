// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package server_test

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/minio/minio-go/v7"
	"github.com/stretchr/testify/require"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"storj.io/common/fpath"
	"storj.io/common/memory"
	"storj.io/common/processgroup"
	"storj.io/common/testcontext"
	"storj.io/common/testrand"
	"storj.io/gateway-mt/auth"
	"storj.io/gateway-mt/internal/minioclient"
	"storj.io/storj/cmd/uplink/cmd"
	"storj.io/storj/private/testplanet"
)

func compileAt(t *testing.T, ctx *testcontext.Context, workDir string, pkg string) string {
	t.Helper()

	var binName string
	if pkg == "" {
		dir, _ := os.Getwd()
		binName = path.Base(dir)
	} else {
		binName = path.Base(pkg)
	}

	if absDir, err := filepath.Abs(workDir); err == nil {
		workDir = absDir
	} else {
		t.Log(err)
	}

	exe := ctx.File("build", binName+".exe")

	/* #nosec G204 */ // This package is only used for test
	cmd := exec.Command("go",
		"build",
		"-race",
		"-tags=unittest",
		"-o", exe, pkg,
	)
	t.Log("exec:", cmd.Args, "dir:", workDir)
	cmd.Dir = workDir

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Error(string(out))
		t.Fatal(err)
	}

	return exe
}

var counter int64

func TestUploadDownload(t *testing.T) {
	t.Parallel()

	testplanet.Run(t, testplanet.Config{
		SatelliteCount: 1, StorageNodeCount: 4, UplinkCount: 1,
	}, func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet) {
		access := planet.Uplinks[0].Access[planet.Satellites[0].ID()]

		// TODO: make address not hardcoded the address selection here may
		// conflict with some automatically bound address.
		gatewayAddr := fmt.Sprintf("127.0.0.1:1100%d", atomic.AddInt64(&counter, 1))
		authSvcAddr := fmt.Sprintf("127.0.0.1:1100%d", atomic.AddInt64(&counter, 1))
		authSvcAddrTLS := fmt.Sprintf("127.0.0.1:1100%d", atomic.AddInt64(&counter, 1))

		gatewayExe := compileAt(t, ctx, "../../cmd", "storj.io/gateway-mt/cmd/gateway-mt")

		authConfig := auth.Config{
			Endpoint:          "http://" + gatewayAddr,
			AuthToken:         "super-secret",
			AllowedSatellites: []string{planet.Satellites[0].NodeURL().String()},
			KVBackend:         "memory://",
			ListenAddr:        authSvcAddr,
			ListenAddrTLS:     authSvcAddrTLS,
		}

		auth, err := auth.New(ctx, zaptest.NewLogger(t).Named("auth"), authConfig, fpath.ApplicationDir("storj", "authservice"))
		require.NoError(t, err)

		defer ctx.Check(auth.Close)

		ctx.Go(func() error { return auth.Run(ctx) })

		require.NoError(t, waitForAuthSvcStart(ctx, authSvcAddr, time.Second))

		// todo: use the unused endpoint below
		accessKey, secretKey, _, err := cmd.RegisterAccess(ctx, access, "http://"+authSvcAddr, false, 15*time.Second)
		require.NoError(t, err)

		client, err := minioclient.NewMinio(minioclient.Config{
			S3Gateway: gatewayAddr,
			Satellite: planet.Satellites[0].Addr(),
			AccessKey: accessKey,
			SecretKey: secretKey,
			APIKey:    planet.Uplinks[0].APIKey[planet.Satellites[0].ID()].Serialize(),
			NoSSL:     true,
		})
		require.NoError(t, err)

		gateway, err := startGateway(ctx, t, client, gatewayExe, gatewayOptions{
			Listen:      gatewayAddr,
			AuthService: authSvcAddr,
		})
		require.NoError(t, err)

		defer func() { processgroup.Kill(gateway) }()

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

			err = rawClient.UploadMultipart(ctx, bucket, objectName, data, partSize.Int(), 0)
			require.NoError(t, err)

			// TODO find out why with prefix set its hanging test
			for objInfo := range rawClient.API.ListObjects(ctx, bucket, minio.ListObjectsOptions{Prefix: ""}) {
				require.Equal(t, objectName, objInfo.Key)

				// Minio adds a double quote to ETag, sometimes.
				// Remove the potential quote from either end.
				etag := strings.TrimPrefix(objInfo.ETag, `"`)
				etag = strings.TrimSuffix(etag, `"`)

				require.Equal(t, expectedETag, etag)
				break
			}

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
			require.False(t, info.PartnerID.IsZero())

			// operating with aws-ask-go that has a default user-agent string
			// set for aws
			newSession, err := session.NewSession(&aws.Config{
				Credentials:      credentials.NewStaticCredentials(accessKey, secretKey, ""),
				Endpoint:         aws.String("http://" + gatewayAddr),
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
			require.NotEqual(t, info.PartnerID.String(), infoWithCustomUserAgent.PartnerID.String())
		}
	})
}

// waitForAuthSvcStart checks if authservice is ready in a constant backoff
// fashion.
func waitForAuthSvcStart(ctx context.Context, authSvcAddress string, maxStartupWait time.Duration) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://%s/v1/health/live", authSvcAddress), nil)
	if err != nil {
		return errs.Wrap(err)
	}

	for start := time.Now(); ; {
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			continue
		}

		if res.Body.Close() != nil {
			continue
		}

		if res.StatusCode == http.StatusOK {
			return nil
		}

		// wait a bit before retrying to reduce load
		time.Sleep(50 * time.Millisecond)

		if time.Since(start) > maxStartupWait {
			return errs.New("exceeded maxStartupWait duration")
		}
	}
}

type gatewayOptions struct {
	Listen      string
	AuthService string

	More []string
}

func startGateway(ctx context.Context, t *testing.T, client minioclient.Client, exe string, opts gatewayOptions) (*exec.Cmd, error) {
	args := append([]string{"run",
		"--server.address", opts.Listen,
		"--auth-token", "super-secret",
		"--auth-url", "http://" + opts.AuthService,
		"--domain-name", "localhost",
	}, opts.More...)

	gateway := exec.Command(exe, args...)

	log := zaptest.NewLogger(t)
	gateway.Stdout = logWriter{log.Named("gateway:stdout")}
	gateway.Stderr = logWriter{log.Named("gateway:stderr")}

	err := gateway.Start()
	if err != nil {
		return nil, err
	}

	err = waitForGatewayStart(ctx, client, opts.Listen, 5*time.Second, gateway)
	if err != nil {
		killErr := gateway.Process.Kill()
		return nil, errs.Combine(err, killErr)
	}

	return gateway, nil
}

func cmdErr(app, action, address string, wait time.Duration, cmd *exec.Cmd) error {
	return fmt.Errorf("%s [%s] did not %s in required time %v\n%s",
		app, address, action, wait, strings.Join(cmd.Args, " "))
}

// waitForGatewayStart will monitor starting when we are able to start the process.
func waitForGatewayStart(ctx context.Context, client minioclient.Client, gatewayAddress string, maxStartupWait time.Duration, cmd *exec.Cmd) error {
	start := time.Now()
	for {
		_, err := client.ListBuckets(ctx)
		if err == nil {
			return nil
		}

		// wait a bit before retrying to reduce load
		time.Sleep(50 * time.Millisecond)

		if time.Since(start) > maxStartupWait {
			return cmdErr("Gateway", "start", gatewayAddress, maxStartupWait, cmd)
		}
	}
}

type logWriter struct{ log *zap.Logger }

func (log logWriter) Write(p []byte) (n int, err error) {
	log.log.Debug(string(p))
	return len(p), nil
}
