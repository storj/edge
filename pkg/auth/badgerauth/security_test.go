// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauth_test

import (
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	mathrand "math/rand"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"storj.io/common/testcontext"
	"storj.io/gateway-mt/pkg/auth/badgerauth"
)

func TestTLSOptions(t *testing.T) {
	t.Parallel()

	ctx := testcontext.New(t)

	opts := badgerauth.TLSOptions{
		CertsDir: ctx.Dir(),
	}

	trusted := createTestingPool(t, 2)
	untrusted := createTestingPool(t, 1)

	err := os.WriteFile(ctx.File("ca.crt"), encodeCertificate(trusted.CA.Raw), 0644)
	require.NoError(t, err)
	err = os.WriteFile(ctx.File("node.crt"), encodeCertificate(trusted.Certs[0].Certificate[0]), 0644)
	require.NoError(t, err)
	err = os.WriteFile(ctx.File("node.key"), encodePrivateKey(trusted.Certs[0].PrivateKey), 0644)
	require.NoError(t, err)

	cfg, err := opts.Load()
	require.NoError(t, err)

	verifyOpts := x509.VerifyOptions{
		Roots:         cfg.ClientCAs,
		CurrentTime:   time.Now(),
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	_, err = trusted.CA.Verify(verifyOpts)
	require.NoError(t, err)
	_, err = trusted.Certs[0].Leaf.Verify(verifyOpts)
	require.NoError(t, err)
	_, err = trusted.Certs[1].Leaf.Verify(verifyOpts)
	require.NoError(t, err)

	_, err = untrusted.CA.Verify(verifyOpts)
	require.Error(t, err)
	_, err = untrusted.Certs[0].Leaf.Verify(verifyOpts)
	require.Error(t, err)
}

type certificatePool struct {
	// CA
	CA         *x509.Certificate
	PrivateKey crypto.PrivateKey
	PublicKey  crypto.PublicKey

	// Certs
	Certs []tls.Certificate
}

func createTestingPool(t *testing.T, count int) certificatePool {
	rng := mathrand.New(mathrand.NewSource(mathrand.Int63()))

	pool := certificatePool{}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		NotAfter:              time.Now().Add(2 * time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	privateKey, err := rsa.GenerateKey(rng, 4096)
	require.NoError(t, err)
	pool.PrivateKey = privateKey
	pool.PublicKey = privateKey.PublicKey

	certDER, err := x509.CreateCertificate(rng, caTemplate, caTemplate, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	pool.CA, err = x509.ParseCertificate(certDER)
	require.NoError(t, err)

	for k := 0; k < count; k++ {
		nodeTemplate := &x509.Certificate{
			SerialNumber:          big.NewInt(int64(42 + k)),
			NotAfter:              time.Now().Add(2 * time.Hour),
			IsCA:                  false,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			IPAddresses:           []net.IP{{127, 0, 0, 1}},
		}

		pk, err := rsa.GenerateKey(rng, 4096)
		require.NoError(t, err)

		certDER, err := x509.CreateCertificate(rng, nodeTemplate, pool.CA, &pk.PublicKey, pool.PrivateKey)
		require.NoError(t, err)

		cert, err := x509.ParseCertificate(certDER)
		require.NoError(t, err)

		tlscert := tls.Certificate{
			PrivateKey:  pk,
			Leaf:        cert,
			Certificate: [][]byte{certDER},
		}
		pool.Certs = append(pool.Certs, tlscert)
	}

	return pool
}

func encodeCertificate(cert []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
}

func encodePrivateKey(key crypto.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key.(*rsa.PrivateKey)),
	})
}
