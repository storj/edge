// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/testcontext"
	"storj.io/gateway-mt/pkg/server"
	"storj.io/gateway-mt/pkg/trustedip"
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

	// create server
	var tlsConfig *tls.Config
	if useTLS {
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{createCert(t, "localhost"), createCert(t, "*.localhost")}}
	}
	config := server.Config{Server: server.AddrConfig{Address: "127.0.0.1:0"}, InsecureLogAll: true, EncodeInMemory: true}
	s, err := server.New(config, zaptest.NewLogger(t), tlsConfig, trustedip.NewListTrustAll(), []string{}, nil, []string{})
	require.NoError(t, err)

	defer ctx.Check(s.Close)

	ctx.Go(s.Run)

	// get url parameters
	_, port, err := net.SplitHostPort(s.Address())
	require.NoError(t, err)
	urlBase := "http://127.0.0.1:" + port + "/"
	if useTLS {
		urlBase = "https://127.0.0.1:" + port + "/"
	}
	client := &http.Client{Timeout: 5 * time.Second}
	if useTLS {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}

	testHealthCheck(ctx, t, urlBase+"-/health", client)
	testVersionInfo(ctx, t, urlBase+"-/version", client)
}

func testHealthCheck(ctx context.Context, t *testing.T, url string, client *http.Client) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	require.NoError(t, err)
	response, err := client.Do(req)
	require.NoError(t, err)
	require.Equal(t, 200, response.StatusCode)
	defer func() { _ = response.Body.Close() }()
}

func testVersionInfo(ctx context.Context, t *testing.T, url string, client *http.Client) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	require.NoError(t, err)
	response, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	require.Equal(t, 200, response.StatusCode)
	body, err := ioutil.ReadAll(response.Body)
	require.NoError(t, err)
	require.Equal(t, "v0.0.0", string(body))
}

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
