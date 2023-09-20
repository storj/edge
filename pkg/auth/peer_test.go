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
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/pb"
	"storj.io/common/rpc"
	"storj.io/common/testcontext"
	"storj.io/gateway-mt/pkg/auth/badgerauth"
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
