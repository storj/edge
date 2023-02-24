// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package server_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/pkcrypto"
	"storj.io/common/testcontext"
	"storj.io/gateway-mt/pkg/server"
	"storj.io/gateway-mt/pkg/trustedip"
)

var (
	testKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgT8yIof+3qG3wQzXf
eAOcuTgWmgqXRnHVwKJl2g1pCb2hRANCAARWxVAPyT1BRs2hqiDuHlPXr1kVDXuw
7/a1USmgsVWiZ0W3JopcTbTMhvMZk+2MKqtWcc3gHF4vRDnHTeQl4lsx
-----END PRIVATE KEY-----`
	testCert = mustCreateLocalhostCert()
)

func TestPathStyle(t *testing.T) {
	t.Parallel()
	testServer(t, false, false, false)
}

func TestVirtualHostStyle(t *testing.T) {
	t.Parallel()
	testServer(t, false, true, false)
}

func TestPathStyleTLS(t *testing.T) {
	t.Parallel()
	testServer(t, true, false, false)
}

func TestVirtualHostStyleTLS(t *testing.T) {
	t.Parallel()
	testServer(t, true, true, false)
}

func TestShutdown(t *testing.T) {
	t.Parallel()
	testServer(t, false, false, true)
}

func testServer(t *testing.T, useTLS, vHostStyle bool, shutdownDelay bool) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	var certDir string
	if useTLS {
		certDir = t.TempDir()
		keyPath := filepath.Join(certDir, "cert.key")
		certPath := filepath.Join(certDir, "cert.crt")

		err := os.WriteFile(keyPath, []byte(testKey), 0644)
		require.NoError(t, err)

		err = os.WriteFile(certPath, pkcrypto.CertToPEM(testCert), 0644)
		require.NoError(t, err)
	}

	delay := 0 * time.Second
	if shutdownDelay {
		delay = 100 * time.Millisecond
	}

	config := server.Config{
		Server: server.AddrConfig{
			Address:    "127.0.0.1:0",
			AddressTLS: "127.0.0.1:0",
		},
		CertDir:        certDir,
		InsecureLogAll: true,
		EncodeInMemory: true,
		ShutdownDelay:  delay,
		DomainName:     "gateway.local,*.gateway.local",
	}
	s, err := server.New(config, zaptest.NewLogger(t), trustedip.NewListTrustAll(), []string{}, nil, 10)
	require.NoError(t, err)

	defer ctx.Check(s.Close)

	ctx.Go(func() error {
		return s.Run(ctx)
	})

	// get url parameters
	scheme := "http"
	_, port, err := net.SplitHostPort(s.Address())
	require.NoError(t, err)
	if useTLS {
		scheme = "https"
		_, port, err = net.SplitHostPort(s.AddressTLS())
		require.NoError(t, err)
	}
	urlBase := scheme + "://127.0.0.1:" + port + "/"
	client := &http.Client{Timeout: 5 * time.Second}
	if useTLS {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPoolFromCert(testCert),
			},
		}
	}

	testHealthCheck(ctx, t, urlBase+"-/health", client)
	testVersionInfo(ctx, t, urlBase+"-/version", client)
	if shutdownDelay {
		testShutdown(ctx, t, s, urlBase+"-/health", client)
	}
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
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Equal(t, "v0.0.0", string(body))
}

func testShutdown(ctx *testcontext.Context, t *testing.T, s *server.Peer, url string, client *http.Client) {
	ctx.Go(s.Close)

	// Make sure the health check returns 503s before the shutdown delay expires
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		require.NoError(t, err)
		response, err := client.Do(req)
		// Shutdown delay expired
		require.NoError(t, err, "health check failed to return expected status before shutdown")
		// Success
		if response.StatusCode == http.StatusServiceUnavailable {
			require.NoError(t, response.Body.Close())
			break
		}
		require.NoError(t, response.Body.Close())
		time.Sleep(20 * time.Millisecond)
	}
}

func mustCreateLocalhostCert() *x509.Certificate {
	key, err := pkcrypto.PrivateKeyFromPEM([]byte(testKey))
	if err != nil {
		panic(err)
	}
	privateKey := key.(crypto.Signer)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, privateKey.Public(), privateKey)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		panic(err)
	}
	return cert
}

func certPoolFromCert(cert *x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}
