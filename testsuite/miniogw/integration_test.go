// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

//lint:file-ignore U1000,SA4010,SA4006 Ignore all unused code, skipped tests
//nolint
package miniogw_test

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
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
	"github.com/stretchr/testify/require"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"storj.io/common/memory"
	"storj.io/common/processgroup"
	"storj.io/common/testcontext"
	"storj.io/common/testrand"
	"storj.io/gateway-mt/internal/minioclient"
	"storj.io/storj/private/testplanet"
	"storj.io/uplink"
)

// todo: remove this when mulitpart is merged
// at the moment testssuite uses storj.io/uplink@multipart-upload
// however, storj.io/uplink@master is the only place where
// "storj.io/storj/cmd/uplink/cmd".RegisterAccess() is defined
// so this function is just a temporary hack
func registerAccess(t *testing.T, authService string, access *uplink.Access) (accessKey, secretKey, endpoint string, err error) {
	accesssSerialized, err := access.Serialize()
	require.NoError(t, err)
	postData, err := json.Marshal(map[string]interface{}{
		"access_grant": accesssSerialized,
		"public":       true,
	})
	require.NoError(t, err)
	resp, err := http.Post(fmt.Sprintf("%s/v1/access", authService), "application/json", bytes.NewReader(postData))
	require.NoError(t, err)
	defer func() { err = errs.Combine(err, resp.Body.Close()) }()

	body, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err)
	respBody := make(map[string]string)
	err = json.Unmarshal(body, &respBody)
	require.NoError(t, err)
	return respBody["access_key_id"], respBody["secret_key"], respBody["endpoint"], nil
}

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

func TestUploadDownload(t *testing.T) {
	var counter int64
	testplanet.Run(t, testplanet.Config{
		SatelliteCount: 1, StorageNodeCount: 4, UplinkCount: 1,
		NonParallel: true,
	}, func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet) {
		access := planet.Uplinks[0].Access[planet.Satellites[0].ID()]

		accessStr, err := access.Serialize()
		require.NoError(t, err)

		// TODO: make address not hardcoded the address selection here
		// may conflict with some automatically bound address.
		gatewayAddr := fmt.Sprintf("127.0.0.1:1100%d", atomic.AddInt64(&counter, 1))
		authSvcAddr := fmt.Sprintf("127.0.0.1:1100%d", atomic.AddInt64(&counter, 1))
		satelliteAddr := planet.Satellites[0].Addr()

		gatewayExe := compileAt(t, ctx, "../../cmd", "storj.io/gateway-mt/cmd/gateway-mt")
		authSvcExe := compileAt(t, ctx, "../../cmd", "storj.io/gateway-mt/cmd/authservice")

		authSvc, err := startAuthSvc(t, authSvcExe, authSvcAddr, gatewayAddr, satelliteAddr)
		require.NoError(t, err)
		defer func() { processgroup.Kill(authSvc) }()

		// todo: use the unused endpoint below
		accessKey, secretKey, _, err := registerAccess(t, "http://"+authSvcAddr, access)
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

		gateway, err := startGateway(t, client, gatewayExe, accessStr, gatewayAddr, authSvcAddr, satelliteAddr)
		require.NoError(t, err)
		defer func() { processgroup.Kill(gateway) }()

		{ // normal upload
			bucket := "bucket"

			err = client.MakeBucket(bucket, "")
			require.NoError(t, err)

			// generate enough data for a remote segment
			data := testrand.BytesInt(5000)
			objectName := "testdata"

			err = client.Upload(bucket, objectName, data)
			require.NoError(t, err)

			buffer := make([]byte, len(data))

			bytes, err := client.Download(bucket, objectName, buffer)
			require.NoError(t, err)

			require.Equal(t, data, bytes)
		}

		{ // multipart upload
			bucket := "bucket-multipart"

			err = client.MakeBucket(bucket, "")
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

			err = rawClient.UploadMultipart(bucket, objectName, data, partSize.Int(), 0)
			require.NoError(t, err)

			// TODO: Restore the below test code when we implement multipart upload again.
			//
			doneCh := make(chan struct{})
			defer close(doneCh)

			// TODO find out why with prefix set its hanging test
			for message := range rawClient.API.ListObjectsV2(bucket, "", true, doneCh) {
				require.Equal(t, objectName, message.Key)
				require.NotEmpty(t, message.ETag)

				// Minio adds a double quote to ETag, sometimes.
				// Remove the potential quote from either end.
				etag := strings.TrimPrefix(message.ETag, `"`)
				etag = strings.TrimSuffix(etag, `"`)

				require.Equal(t, expectedETag, etag)
				break
			}

			buffer := make([]byte, len(data))
			bytes, err := client.Download(bucket, objectName, buffer)
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

func startAuthSvc(t *testing.T, exe, authSvcAddress, gatewayAddress, satelliteAddress string, moreFlags ...string) (*exec.Cmd, error) {
	args := append([]string{"run",
		"--auth-token", "super-secret",
		"--allowed-satellites", satelliteAddress,
		"--endpoint", "http://" + gatewayAddress,
		"--listen-addr", authSvcAddress,
	}, moreFlags...)

	authSvc := exec.Command(exe, args...)

	log := zaptest.NewLogger(t)
	authSvc.Stdout = logWriter{log.Named("authsvc:stdout")}
	authSvc.Stderr = logWriter{log.Named("authsvc:stderr")}

	err := authSvc.Start()
	if err != nil {
		return nil, err
	}

	err = waitForAuthSvcStart(authSvcAddress, 5*time.Second, authSvc)
	if err != nil {
		killErr := authSvc.Process.Kill()
		return nil, errs.Combine(err, killErr)
	}

	return authSvc, nil
}

// waitForAuthSvcStart will monitor starting when we are able to start the process.
func waitForAuthSvcStart(authSvcAddress string, maxStartupWait time.Duration, cmd *exec.Cmd) error {
	start := time.Now()
	for {
		_, err := http.Get("http://" + authSvcAddress)
		if err == nil {
			return nil
		}

		// wait a bit before retrying to reduce load
		time.Sleep(50 * time.Millisecond)

		if time.Since(start) > maxStartupWait {
			return cmdErr("AuthSvc", "start", authSvcAddress, maxStartupWait, cmd)
		}
	}
}

func stopAuthSvc(authSvc *exec.Cmd, authSvcAddress string, cmd *exec.Cmd) error {
	err := authSvc.Process.Kill()
	if err != nil {
		return err
	}

	start := time.Now()
	maxStopWait := 5 * time.Second
	for {
		if !tryConnectAuthSvc(authSvcAddress) {
			return nil
		}

		// wait a bit before retrying to reduce load
		time.Sleep(50 * time.Millisecond)

		if time.Since(start) > maxStopWait {
			return cmdErr("AuthSvc", "stop", authSvcAddress, maxStopWait, cmd)
		}
	}
}

// tryConnectAuthSvc will try to connect to the process public address.
func tryConnectAuthSvc(authSvcAddress string) bool {
	_, err := http.Get("http://" + authSvcAddress)
	return err == nil
}

func startGateway(t *testing.T, client minioclient.Client, exe, access, gatewayAddress,
	authSvcAddress, satelliteAddr string, moreFlags ...string) (*exec.Cmd, error) {
	args := append([]string{"run",
		"--server.address", gatewayAddress,
		"--multipart-upload-satellites", satelliteAddr,
		"--auth-token", "super-secret",
		"--auth-url", "http://" + authSvcAddress,
		"--domain-name", "localhost",
	}, moreFlags...)

	gateway := exec.Command(exe, args...)

	log := zaptest.NewLogger(t)
	gateway.Stdout = logWriter{log.Named("gateway:stdout")}
	gateway.Stderr = logWriter{log.Named("gateway:stderr")}

	err := gateway.Start()
	if err != nil {
		return nil, err
	}

	err = waitForGatewayStart(client, gatewayAddress, 5*time.Second, gateway)
	if err != nil {
		killErr := gateway.Process.Kill()
		return nil, errs.Combine(err, killErr)
	}

	return gateway, nil
}

func cmdErr(app, action, address string, wait time.Duration, cmd *exec.Cmd) error {
	return fmt.Errorf("%s [%s] did not %s in required time %v\n%s\n",
		app, address, action, wait, strings.Join(cmd.Args, " "))
}

func stopGateway(gateway *exec.Cmd, gatewayAddress string) error {
	err := gateway.Process.Kill()
	if err != nil {
		return err
	}

	start := time.Now()
	maxStopWait := 5 * time.Second
	for {
		if !tryConnectGateway(gatewayAddress) {
			return nil
		}

		// wait a bit before retrying to reduce load
		time.Sleep(50 * time.Millisecond)

		if time.Since(start) > maxStopWait {
			return cmdErr("Gateway", "stop", gatewayAddress, maxStopWait, gateway)
		}
	}
}

// waitForGatewayStart will monitor starting when we are able to start the process.
func waitForGatewayStart(client minioclient.Client, gatewayAddress string, maxStartupWait time.Duration, cmd *exec.Cmd) error {
	start := time.Now()
	for {
		_, err := client.ListBuckets()
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

// tryConnect will try to connect to the process public address.
func tryConnectGateway(gatewayAddress string) bool {
	conn, err := net.Dial("tcp", gatewayAddress)
	if err != nil {
		return false
	}
	// write empty byte slice to trigger refresh on connection
	_, _ = conn.Write([]byte{})
	// ignoring errors, because we only care about being able to connect
	_ = conn.Close()
	return true
}

type logWriter struct{ log *zap.Logger }

func (log logWriter) Write(p []byte) (n int, err error) {
	log.log.Debug(string(p))
	return len(p), nil
}
