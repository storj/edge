// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package server_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"storj.io/common/errs2"
	"storj.io/common/testcontext"
	"storj.io/gateway-mt/pkg/server"
)

func TestPathStyle(t *testing.T) {
	t.Parallel()
	testServer(t, false, false)
}
func TestVirtualHostStyle(t *testing.T) {
	t.Parallel()
	testServer(t, false, true)
}

func TestPathStyleTLS(t *testing.T) {
	t.Parallel()
	testServer(t, true, false)
}
func TestVirtualHostStyleTLS(t *testing.T) {
	t.Parallel()
	testServer(t, true, true)
}

func testServer(t *testing.T, useTLS, vHostStyle bool) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()
	core, logs := observer.New(zapcore.DebugLevel)

	// create server
	listener, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	config := server.Config{DomainNames: []string{"localhost"}, Address: "127.0.0.1:0"}
	var tlsConfig *tls.Config
	if useTLS {
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{createCert(t, "localhost"), createCert(t, "*.localhost")}}
	}
	s := server.New(listener, zap.New(core), tlsConfig, config)
	ctx.Go(func() error {
		return errs2.IgnoreCanceled(s.Run(ctx))
	})
	defer ctx.Check(s.Close)

	// get url parameters
	_, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	urlBase := "http://127.0.0.1:" + port + "/"
	if useTLS {
		urlBase = "https://127.0.0.1:" + port + "/"
	}
	bucket := urlBase + "bucket"
	object := urlBase + "bucket/key"
	if vHostStyle {
		bucket = urlBase
		object = urlBase + "key"
	}

	client := &http.Client{Timeout: 5 * time.Second}
	if useTLS {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}

	testHealthCheck(t, urlBase+"-/health", client)
	testRouting(t, logs, urlBase, bucket, object, vHostStyle, client)
	// testRoute(t, logs, "ListBuckets", urlBase, http.MethodGet, false, false, client)
}

func testHealthCheck(t *testing.T, url string, client *http.Client) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	require.NoError(t, err)
	response, err := client.Do(req)
	require.NoError(t, err)
	require.Equal(t, 200, response.StatusCode)
	defer func() { _ = response.Body.Close() }()
}

func testRouting(t *testing.T, logs *observer.ObservedLogs, urlBase, bucket, object string, vHostStyle bool, client *http.Client) {
	// Trust the augmented cert pool in our client

	// testRoute(t, logs, "DeleteObjectTagging", object+"?tagging", http.MethodDelete, false, vHostStyle, client)
	// testRoute(t, logs, "GetObjectTagging", object+"?tagging", http.MethodGet, false, vHostStyle, client)
	// testRoute(t, logs, "PutObjectTagging", object+"?tagging", http.MethodPut, false, vHostStyle, client)

	// testRoute(t, logs, "CreateMultipartUpload", object+"?uploads", http.MethodPost, false, vHostStyle, client)
	// testRoute(t, logs, "AbortMultipartUpload", object+"?uploadId=UploadId", http.MethodDelete, false, vHostStyle, client)
	// testRoute(t, logs, "ListParts", object+"?uploadId=UploadId", http.MethodGet, false, vHostStyle, client)
	// testRoute(t, logs, "CompleteMultipartUpload", object+"?uploadId=UploadId", http.MethodPost, false, vHostStyle, client)
	// testRoute(t, logs, "UploadPartCopy", object+"?uploadId=UploadId&partNumber=PartNumber", http.MethodPut, true, vHostStyle, client)
	// testRoute(t, logs, "UploadPart", object+"?uploadId=UploadId&partNumber=PartNumber", http.MethodPut, false, vHostStyle, client)

	// testRoute(t, logs, "GetObject", object, http.MethodGet, false, vHostStyle, client)
	// testRoute(t, logs, "CopyObject", object, http.MethodPut, true, vHostStyle, client)
	// testRoute(t, logs, "PutObject", object, http.MethodPut, false, vHostStyle, client)
	// testRoute(t, logs, "DeleteObject", object, http.MethodDelete, false, vHostStyle, client)
	// testRoute(t, logs, "HeadObject", object, http.MethodHead, false, vHostStyle, client)

	// testRoute(t, logs, "DeleteBucketTagging", bucket+"?tagging", http.MethodDelete, false, vHostStyle, client)
	// testRoute(t, logs, "GetBucketTagging", bucket+"?tagging", http.MethodGet, false, vHostStyle, client)
	// testRoute(t, logs, "PutBucketTagging", bucket+"?tagging", http.MethodPut, false, vHostStyle, client)

	// testRoute(t, logs, "DeleteObjects", bucket+"?delete", http.MethodPost, false, vHostStyle, client)
	// testRoute(t, logs, "ListMultipartUploads", bucket+"?uploads", http.MethodGet, false, vHostStyle, client)
	// testRoute(t, logs, "ListObjectsV2", bucket+"?list-type=2", http.MethodGet, false, vHostStyle, client)

	// testRoute(t, logs, "ListObjects", bucket, http.MethodGet, false, vHostStyle, client)
	// testRoute(t, logs, "CreateBucket", bucket, http.MethodPut, false, vHostStyle, client)
	// testRoute(t, logs, "DeleteBucket", bucket, http.MethodDelete, false, vHostStyle, client)
	// testRoute(t, logs, "HeadBucket", bucket, http.MethodHead, false, vHostStyle, client)
}

// func testRoute(t *testing.T, logs *observer.ObservedLogs, expectedLog, url, httpMethod string, addAmzCopyHeader, vHostStyle bool, client *http.Client) {
// 	req, err := http.NewRequest(httpMethod, url, nil)
// 	require.NoError(t, err)
// 	if addAmzCopyHeader {
// 		req.Header.Set("x-amz-copy-source", "any value currently works for testing")
// 	}
// 	if vHostStyle {
// 		req.Host = "bucket.localhost"
// 	} else {
// 		// not every machine might have a localhost mapping
// 		// so this will set the HTTP host header as desired
// 		req.Host = "localhost"
// 	}
// 	response, err := client.Do(req)
// 	require.NoError(t, err)
// 	defer func() { _ = response.Body.Close() }()
// 	require.Equal(t, 1, len(logs.All()), expectedLog)
// 	assert.Equal(t, expectedLog, logs.TakeAll()[0].Message)
// }

func createCert(t *testing.T, host string) tls.Certificate {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	require.NoError(t, err)
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"Storj Labs"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
		IsCA:                  true,
	}
	priv1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	derBytes1, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv1.PublicKey, priv1)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{derBytes1}, PrivateKey: priv1}
}
