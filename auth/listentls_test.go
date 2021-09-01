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
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/pb"
	"storj.io/common/rpc"
	"storj.io/common/testcontext"
)

func TestTLS(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	certFile, keyFile, certificatePEM, _ := createSelfSignedCertificateFile(t, "localhost")

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := strings.ReplaceAll(listener.Addr().String(), "127.0.0.1", "localhost")

	tlsInfo := &TLSInfo{
		CertFile:  certFile.Name(),
		KeyFile:   keyFile.Name(),
		PublicURL: "https://" + address,
	}

	tlsConfig, handler, err := configureTLS(tlsInfo, nil)
	require.NoError(t, err)

	serverCtx, serverCancel := context.WithCancel(ctx)
	defer func() {
		serverCancel()
		ctx.Wait()
	}()

	ctx.Go(func() error {
		return listenAndServe(
			serverCtx,
			zaptest.NewLogger(t),
			listener,
			tlsConfig,
			&DRPCServerMock{},
			handler,
		)
	})

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certificatePEM)

	dialer := rpc.NewDefaultDialer(nil)
	dialer.HostnameTLSConfig = &tls.Config{
		RootCAs: certPool,
	}

	connection, err := dialer.DialAddressHostnameVerification(ctx, address)
	require.NoError(t, err)

	drpcClient := pb.NewDRPCEdgeAuthClient(connection)

	accessGrant := "1JdRhtpnQUH3KggvmzfMhUT9pDTF9L8CFZoU5NynjRmaVQ4mCev6ZAGiPrpTem5PcfEEFTRioDk4eed2uJADVAvtSH3ETdbokBy7o3355ih9rJ2j5h8vC9yrVrdRjnAdwvaEJADJJTbL8VqZT6Jksd5tP6roMQbwZog9RNoSKMjb71Z9TAG1dTGLfqpBV5nsktyZaGdsru32Wk7BCvNQV3VdgPmax6AGPdnv4WNBrzmLVNQzhpHGx9LsKzfECtQMQTdrmULgqUiJBFoUafB"

	registerAccessResponse, err := drpcClient.RegisterAccess(ctx, &pb.EdgeRegisterAccessRequest{
		AccessGrant: accessGrant,
		Public:      false,
	})
	require.NoError(t, err)

	require.Equal(t, "accesskeyid", registerAccessResponse.AccessKeyId)
	require.Equal(t, "secretkey", registerAccessResponse.SecretKey)
	require.Equal(t, "endpoint", registerAccessResponse.Endpoint)
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

func createSelfSignedCertificateFile(t *testing.T, hostname string) (certFile *os.File, keyFile *os.File, certificatePEM []byte, privateKeyPEM []byte) {
	certificatePEM, privateKeyPEM = createSelfSignedCertificate(t, hostname)

	certFile, err := ioutil.TempFile(os.TempDir(), "*-cert.pem")
	require.NoError(t, err)
	_, err = certFile.Write(certificatePEM)
	require.NoError(t, err)

	keyFile, err = ioutil.TempFile(os.TempDir(), "*-key.pem")
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
