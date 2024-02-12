// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/stretchr/testify/require"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest"
	"go.uber.org/zap/zaptest/observer"

	"storj.io/common/errs2"
	"storj.io/common/pb"
	"storj.io/common/rpc"
	"storj.io/common/testcontext"
	"storj.io/common/testrand"
	"storj.io/edge/pkg/auth/badgerauth"
)

// TestPeer_Close ensures that closing bare Peer with minimal config it needs to
// start will not panic and has released all the resources.
func TestPeer_Close(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	p, err := New(ctx, zaptest.NewLogger(t), Config{
		Endpoint:          "https://example.com",
		AllowedSatellites: []string{"https://www.storj.io/dcs-satellites"},
		KVBackend:         "badger://",
		Node: badgerauth.Config{
			FirstStart:          true,
			ReplicationInterval: 5 * time.Second,
		},
	}, "")
	require.NoError(t, err)

	require.NotPanics(t, func() {
		require.NoError(t, p.Close())
	})
}

func TestPeer_BadListenerError(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	config := Config{
		Endpoint:          "https://example.com",
		AllowedSatellites: []string{"https://www.storj.io/dcs-satellites"},
		KVBackend:         "badger://",
		ListenAddr:        "127.0.0.1:0",
		DRPCListenAddr:    "127.0.0.1:0",
		Node: badgerauth.Config{
			FirstStart:          true,
			ReplicationInterval: 5 * time.Second,
		},
	}

	p, err := New(ctx, zaptest.NewLogger(t), config, "")
	require.NoError(t, err)
	defer ctx.Check(p.Close)

	// fails to listen when the address is already taken.
	config.DRPCListenAddr = p.DRPCAddress()
	_, err = New(ctx, zaptest.NewLogger(t), config, "")
	require.Error(t, err)

	// closing the peer means we can use the address again.
	require.NoError(t, p.Close())
	_, err = New(ctx, zaptest.NewLogger(t), config, "")
	require.NoError(t, err)
}

type DRPCServerMock struct {
	pb.DRPCEdgeAuthServer
}

func (g *DRPCServerMock) RegisterAccess(context.Context, *pb.EdgeRegisterAccessRequest) (*pb.EdgeRegisterAccessResponse, error) {
	return &pb.EdgeRegisterAccessResponse{
		AccessKeyId: "accesskeyid",
		SecretKey:   "secretkey",
		Endpoint:    "endpoint",
	}, nil
}

func TestPeer_PlainDRPC(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	serverCtx, serverCancel := context.WithCancel(ctx)
	defer serverCancel()

	type MockHTTPHandler struct {
		http.Handler
	}

	httpServer := &http.Server{
		Handler: MockHTTPHandler{},
	}

	defer ctx.Check(httpServer.Close)

	p, err := New(ctx, zaptest.NewLogger(t), Config{
		Endpoint:          "https://example.com",
		AllowedSatellites: []string{"https://www.storj.io/dcs-satellites"},
		KVBackend:         "badger://",
		Node: badgerauth.Config{
			FirstStart:          true,
			ReplicationInterval: 5 * time.Second,
		},
	}, "")
	require.NoError(t, err)

	p.drpcServer = &DRPCServerMock{}

	ctx.Go(func() error {
		return p.ServeDRPC(serverCtx, listener)
	})

	dialer := rpc.NewDefaultDialer(nil)
	connector := rpc.NewHybridConnector()
	connector.SetSendDRPCMuxHeader(false)
	dialer.Connector = connector

	connection, err := dialer.DialAddressUnencrypted(ctx, listener.Addr().String())
	require.NoError(t, err)

	drpcClient := pb.NewDRPCEdgeAuthClient(connection)

	accessGrant := "1NfEFS9eR2QA5o6dov3QGNWrFRYZcufde1EcfS99cJB5ZewJZrWpJEZXat1d1GViu5R8G9NDjKz2z4nBUsmSyA6vPeUAnVheFARypytybCHCV8VcEPd1RyebPJ1apQQY8hNjk4r4v5Pe1sUULBERgemuPfcNMjMh5RUWfP1aNm7UFZToeV1ALKVKZCeetrnc8V2gaDz6R28Eaat62Xz7RBAmsfbJZ86GoDpw2PUrVMBGD9gtiRJiqTG7G"

	registerAccessResponse, err := drpcClient.RegisterAccess(ctx, &pb.EdgeRegisterAccessRequest{
		AccessGrant: accessGrant,
		Public:      false,
	})
	require.NoError(t, err)

	require.Equal(t, "accesskeyid", registerAccessResponse.AccessKeyId)
	require.Equal(t, "secretkey", registerAccessResponse.SecretKey)
	require.Equal(t, "endpoint", registerAccessResponse.Endpoint)
}

func TestPeer_TLSDRPC(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	certFile, keyFile, certificatePEM, _ := createSelfSignedCertificateFile(t, "localhost")

	certificate, err := tls.LoadX509KeyPair(certFile.Name(), keyFile.Name())
	require.NoError(t, err)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
	})

	require.NoError(t, err)
	address := strings.ReplaceAll(listener.Addr().String(), "127.0.0.1", "localhost")

	serverCtx, serverCancel := context.WithCancel(ctx)
	defer serverCancel()

	type MockHTTPHandler struct {
		http.Handler
	}

	httpServer := &http.Server{
		Handler: MockHTTPHandler{},
	}
	defer func() {
		err := httpServer.Close()
		require.NoError(t, err)
	}()

	p, err := New(ctx, zaptest.NewLogger(t), Config{
		Endpoint:          "https://example.com",
		AllowedSatellites: []string{"https://www.storj.io/dcs-satellites"},
		KVBackend:         "badger://",
		Node: badgerauth.Config{
			FirstStart:          true,
			ReplicationInterval: 5 * time.Second,
		},
	}, "")
	require.NoError(t, err)

	p.drpcServer = &DRPCServerMock{}

	ctx.Go(func() error {
		return p.ServeDRPC(serverCtx, listener)
	})

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certificatePEM)

	dialer := rpc.NewDefaultDialer(nil)
	dialer.HostnameTLSConfig = &tls.Config{
		RootCAs: certPool,
	}
	connector := rpc.NewHybridConnector()
	connector.SetSendDRPCMuxHeader(false)
	dialer.Connector = connector

	connection, err := dialer.DialAddressHostnameVerification(ctx, address)
	require.NoError(t, err)

	drpcClient := pb.NewDRPCEdgeAuthClient(connection)

	accessGrant := "1NfEFS9eR2QA5o6dov3QGNWrFRYZcufde1EcfS99cJB5ZewJZrWpJEZXat1d1GViu5R8G9NDjKz2z4nBUsmSyA6vPeUAnVheFARypytybCHCV8VcEPd1RyebPJ1apQQY8hNjk4r4v5Pe1sUULBERgemuPfcNMjMh5RUWfP1aNm7UFZToeV1ALKVKZCeetrnc8V2gaDz6R28Eaat62Xz7RBAmsfbJZ86GoDpw2PUrVMBGD9gtiRJiqTG7G"

	registerAccessResponse, err := drpcClient.RegisterAccess(ctx, &pb.EdgeRegisterAccessRequest{
		AccessGrant: accessGrant,
		Public:      false,
	})
	require.NoError(t, err)

	require.Equal(t, "accesskeyid", registerAccessResponse.AccessKeyId)
	require.Equal(t, "secretkey", registerAccessResponse.SecretKey)
	require.Equal(t, "endpoint", registerAccessResponse.Endpoint)
}

func TestPeer_ProxyProtocol(t *testing.T) {
	ctx := testcontext.NewWithTimeout(t, time.Minute)
	defer ctx.Cleanup()

	certFile, keyFile, certificatePEM, _ := createSelfSignedCertificateFile(t, "localhost")

	stdCore := zapcore.NewCore(
		zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()),
		zapcore.Lock(os.Stdout),
		zap.DebugLevel,
	)
	observedCore, observedLogs := observer.New(zap.DebugLevel)
	logger := zap.New(zapcore.NewTee(stdCore, observedCore))

	p, err := New(ctx, logger, Config{
		Endpoint:          "https://example.com",
		AllowedSatellites: []string{testrand.NodeID().String() + "@127.0.0.1:7777"},
		KVBackend:         "badger://",
		ProxyAddrTLS:      "127.0.0.1:0",
		CertFile:          certFile.Name(),
		KeyFile:           keyFile.Name(),
		Node: badgerauth.Config{
			FirstStart:          true,
			ReplicationInterval: 5 * time.Second,
		},
	}, "")
	require.NoError(t, err)

	serverCtx, serverCancel := context.WithCancel(ctx)
	defer serverCancel()

	ctx.Go(func() error {
		return errs2.IgnoreCanceled(p.Run(serverCtx))
	})

	expectedClientAddr := &net.TCPAddr{
		IP: net.IPv4(11, 22, 33, 44),
	}

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certificatePEM)

	// send a PROXY protocol request to the server
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				d := &net.Dialer{}
				conn, err := d.DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}

				tcpAddr, err := net.ResolveTCPAddr(network, addr)
				if err != nil {
					return nil, errs.Combine(err, conn.Close())
				}

				header := proxyproto.HeaderProxyFromAddrs(0, expectedClientAddr, tcpAddr)
				if _, err = header.WriteTo(conn); err != nil {
					return nil, errs.Combine(err, conn.Close())
				}

				return conn, nil
			},
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s/v1/health/startup", p.ProxyAddressTLS()), nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	// ensure the server was able to log the client's IP
	logs := observedLogs.All()
	require.NotEmpty(t, logs)

	logs = observedLogs.FilterMessage("request").All()
	require.NotEmpty(t, logs)

	fields, ok := logs[0].ContextMap()["httpRequest"].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, expectedClientAddr.IP.String(), fields["remoteIp"])
}

func createSelfSignedCertificateFile(t *testing.T, hostname string) (certFile *os.File, keyFile *os.File, certificatePEM []byte, privateKeyPEM []byte) {
	certificatePEM, privateKeyPEM = createSelfSignedCertificate(t, hostname)

	certFile, err := os.CreateTemp(os.TempDir(), "*-cert.pem")
	require.NoError(t, err)
	_, err = certFile.Write(certificatePEM)
	require.NoError(t, err)

	keyFile, err = os.CreateTemp(os.TempDir(), "*-key.pem")
	require.NoError(t, err)
	_, err = keyFile.Write(privateKeyPEM)
	require.NoError(t, err)

	return certFile, keyFile, certificatePEM, privateKeyPEM
}

func createSelfSignedCertificate(t *testing.T, hostname string) (certificatePEM []byte, privateKeyPEM []byte) {
	notAfter := time.Now().Add(1 * time.Minute)

	// first create a server certificate
	template := x509.Certificate{
		Subject: pkix.Name{
			CommonName: hostname,
		},
		DNSNames:              []string{hostname},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		SerialNumber:          big.NewInt(1337),
		BasicConstraintsValid: false,
		IsCA:                  true,
		NotAfter:              notAfter,
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	certificateDERBytes, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		&privateKey.PublicKey,
		privateKey,
	)
	require.NoError(t, err)

	certificatePEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDERBytes})

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	privateKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes})

	return certificatePEM, privateKeyPEM
}
