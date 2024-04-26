// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package httpserver_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/net/http2"

	"storj.io/common/pkcrypto"
	"storj.io/common/testcontext"
	"storj.io/edge/pkg/httpserver"
	"storj.io/edge/pkg/linksharing/objectmap"
	"storj.io/edge/pkg/linksharing/sharing"
	"storj.io/edge/pkg/linksharing/sharing/assets"
)

var (
	testKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgT8yIof+3qG3wQzXf
eAOcuTgWmgqXRnHVwKJl2g1pCb2hRANCAARWxVAPyT1BRs2hqiDuHlPXr1kVDXuw
7/a1USmgsVWiZ0W3JopcTbTMhvMZk+2MKqtWcc3gHF4vRDnHTeQl4lsx
-----END PRIVATE KEY-----`
	testCert = mustCreateLocalhostCert()
)

func TestServer(t *testing.T) {
	address := "localhost:15001"
	handlerConfig := sharing.Config{
		Assets:        assets.FS(),
		ListPageLimit: 1,
		URLBases:      []string{"https://localhost:15001"},
	}
	mapper := objectmap.NewIPDB(&objectmap.MockReader{})
	handler, err := sharing.NewHandler(zaptest.NewLogger(t), mapper, nil, nil, nil, nil, handlerConfig)
	require.NoError(t, err)

	tempdir := t.TempDir()
	keyPath := filepath.Join(tempdir, "privkey.pem")
	certPath := filepath.Join(tempdir, "public.pem")

	err = os.WriteFile(keyPath, []byte(testKey), 0644)
	require.NoError(t, err)

	err = os.WriteFile(certPath, pkcrypto.CertToPEM(testCert), 0644)
	require.NoError(t, err)

	tlsConfig := &httpserver.TLSConfig{
		CertFile:            certPath,
		KeyFile:             keyPath,
		ConfigDir:           tempdir,
		CertMagicPublicURLs: []string{address},
	}

	noTLSConfig := &httpserver.TLSConfig{
		CertFile:            "",
		KeyFile:             "",
		ConfigDir:           tempdir,
		CertMagicPublicURLs: []string{address},
	}

	testCases := []serverTestCase{
		{
			Mapper:        mapper,
			HandlerConfig: handlerConfig,
			Name:          "missing address",
			TLSConfig:     noTLSConfig,
			Handler:       handler,
			NewErr:        "server address is required",
		},
		{
			Mapper:        mapper,
			HandlerConfig: handlerConfig,
			Name:          "bad address",
			Address:       "this is no good",
			TLSConfig:     noTLSConfig,
			Handler:       handler,
			NewErr:        "unable to listen on this is no good: listen tcp: address this is no good: missing port in address",
		},
		{
			Mapper:        mapper,
			HandlerConfig: handlerConfig,
			Name:          "missing handler",
			Address:       address,
			TLSConfig:     noTLSConfig,
			NewErr:        "server handler is required",
		},
		{
			Mapper:        mapper,
			HandlerConfig: handlerConfig,
			Name:          "success via HTTP",
			Address:       address,
			TLSConfig:     noTLSConfig,
			Handler:       handler,
		},
		{
			Mapper:        mapper,
			HandlerConfig: handlerConfig,
			Name:          "success via HTTPS",
			Address:       address,
			AddressTLS:    "localhost:15002",
			TLSConfig:     tlsConfig,
			Handler:       handler,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.Name, func(t *testing.T) {
			ctx := testcontext.NewWithTimeout(t, time.Minute)
			defer ctx.Cleanup()

			s, ok := testCase.NewServer(t)
			if !ok {
				return
			}

			defer ctx.Check(s.Shutdown)

			ctx.Go(func() error {
				return s.Run(ctx)
			})

			testCase.DoGet(ctx, t)
		})
	}
}

func TestProxyProtocol(t *testing.T) {
	ctx := testcontext.NewWithTimeout(t, time.Minute)
	defer ctx.Cleanup()

	tempDir := t.TempDir()

	keyPath := filepath.Join(tempDir, "privkey.pem")
	err := os.WriteFile(keyPath, []byte(testKey), 0644)
	require.NoError(t, err)

	certPath := filepath.Join(tempDir, "public.pem")
	err = os.WriteFile(certPath, pkcrypto.CertToPEM(testCert), 0644)
	require.NoError(t, err)

	// set up the server
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	observedZapCore, observedLogs := observer.New(zap.DebugLevel)
	observedLogger := zap.New(observedZapCore)

	server, err := httpserver.New(observedLogger, mux, nil, httpserver.Config{
		Name:            "test",
		Address:         "127.0.0.1:0",
		AddressTLS:      "127.0.0.1:0",
		ProxyAddressTLS: "127.0.0.1:0",
		TLSConfig: &httpserver.TLSConfig{
			CertFile:  certPath,
			KeyFile:   keyPath,
			ConfigDir: tempDir,
		},
		TrafficLogging: true,
	})
	require.NoError(t, err)

	defer ctx.Check(server.Shutdown)

	ctx.Go(func() error {
		return server.Run(ctx)
	})

	expectedClientAddr := &net.TCPAddr{
		IP: net.IPv4(11, 22, 33, 44),
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialTLSContext: proxyProtocolDialContext(expectedClientAddr, &tls.Config{
				RootCAs:    certPoolFromCert(testCert),
				ServerName: "127.0.0.1",
			}),
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s", server.ProxyAddrTLS()), nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	// ensure the server was able to log the client's IP
	logs := observedLogs.All()
	require.NotEmpty(t, logs)

	logs = observedLogs.FilterMessage("access").All()
	require.NotEmpty(t, logs)

	fields, ok := logs[0].ContextMap()["httpRequest"].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, expectedClientAddr.IP.String(), fields["remoteIp"])
}

func TestBaseTLSConfig(t *testing.T) {
	serverCfg := httpserver.Config{}
	require.Contains(t, serverCfg.BaseTLSConfig().NextProtos, http2.NextProtoTLS)
	serverCfg.DisableHTTP2 = true
	require.NotContains(t, serverCfg.BaseTLSConfig().NextProtos, http2.NextProtoTLS)
}

type serverTestCase struct {
	Mapper        *objectmap.IPDB
	HandlerConfig sharing.Config
	Name          string
	Address       string
	AddressTLS    string
	Handler       http.Handler
	TLSConfig     *httpserver.TLSConfig
	NewErr        string
}

func (testCase *serverTestCase) NewServer(tb testing.TB) (*httpserver.Server, bool) {
	s, err := httpserver.New(zaptest.NewLogger(tb), testCase.Handler, nil, httpserver.Config{
		Name:       "test",
		Address:    testCase.Address,
		AddressTLS: testCase.AddressTLS,
		TLSConfig:  testCase.TLSConfig,
	})
	if testCase.NewErr != "" {
		require.EqualError(tb, err, testCase.NewErr)
		return nil, false
	}
	require.NoError(tb, err)
	return s, true
}

func (testCase *serverTestCase) DoGet(ctx context.Context, tb testing.TB) {
	scheme := "http"
	client := &http.Client{}
	addr := testCase.Address
	if testCase.AddressTLS != "" {
		scheme = "https"
		addr = testCase.AddressTLS
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPoolFromCert(testCert),
			},
		}
	}

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s://%s", scheme, addr), nil)
	require.NoError(tb, err)

	resp, err := client.Do(req)
	require.NoError(tb, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(tb, resp.StatusCode, http.StatusBadRequest)

	body, err := io.ReadAll(resp.Body)
	require.NoError(tb, err)
	assert.True(tb, strings.HasPrefix(strings.ToLower(string(body)), "<!doctype html>\n"))
}

func mustSignerFromPEM(keyBytes string) crypto.Signer {
	key, err := pkcrypto.PrivateKeyFromPEM([]byte(keyBytes))
	if err != nil {
		panic(err)
	}
	return key.(crypto.Signer)
}

func mustCreateLocalhostCert() *x509.Certificate {
	privateKey := mustSignerFromPEM(testKey)
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

func proxyProtocolDialContext(clientAddr net.Addr, tlsConfig *tls.Config) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (conn net.Conn, err error) {
		conn, err = (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		tcpAddr, err := net.ResolveTCPAddr(network, addr)
		if err != nil {
			return nil, errs.Combine(err, conn.Close())
		}

		header := proxyproto.HeaderProxyFromAddrs(0, clientAddr, tcpAddr)
		if _, err = header.WriteTo(conn); err != nil {
			return nil, errs.Combine(err, conn.Close())
		}

		if tlsConfig != nil {
			tlsConn := tls.Client(conn, tlsConfig)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				return nil, errs.Combine(err, conn.Close())
			}
			conn = tlsConn
		}

		return conn, nil
	}
}
