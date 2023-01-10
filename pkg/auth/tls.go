// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package auth

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"os"

	"github.com/caddyserver/certmagic"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/gateway-mt/pkg/certstorage"
)

// TLSInfo is a struct to handle the preferred/configured TLS options.
type TLSInfo struct {
	CertFile   string
	KeyFile    string
	PublicURL  []string
	ConfigDir  string
	ListenAddr string

	// CertMagic obtains and renews TLS certificates and staples OCSP responses
	// Setting this to true will mean the server obtains certificate through Certmagic
	// CertFile and KeyFile options will NOT be considered.
	CertMagic bool

	// CertMagicKeyFile is a path to a file containing the CertMagic service account key.
	CertMagicKeyFile string

	// CertMagicEmail is the email address to use when creating an ACME account
	CertMagicEmail string

	// CertMagicStaging use staging CA endpoints
	CertMagicStaging bool

	// CertMagicBucket bucket to use for certstorage
	CertMagicBucket string
}

func configureTLS(ctx context.Context, log *zap.Logger, config *TLSInfo, handler http.Handler) (*tls.Config, http.Handler, error) {
	if config.CertMagic {
		tlsConfig, err := configureCertMagic(ctx, log, config)
		return tlsConfig, handler, err
	}

	switch {
	case config.CertFile != "" && config.KeyFile != "":
	case config.CertFile == "" && config.KeyFile == "":
		return nil, handler, nil
	case config.CertFile != "" && config.KeyFile == "":
		return nil, nil, errs.New("key file must be provided with cert file")
	case config.CertFile == "" && config.KeyFile != "":
		return nil, nil, errs.New("cert file must be provided with key file")
	}

	cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		return nil, nil, errs.New("unable to load server keypair: %v", err)
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}, handler, nil
}

func configureCertMagic(ctx context.Context, log *zap.Logger, config *TLSInfo) (*tls.Config, error) {
	// Use the GCS cert storage backend
	jsonKey, err := os.ReadFile(config.CertMagicKeyFile)
	if err != nil {
		return nil, errs.New("unable to read cert-magic-key-file: %v", err)
	}
	cs, err := certstorage.NewGCS(ctx, log, jsonKey, config.CertMagicBucket)
	if err != nil {
		return nil, errs.New("initializing certstorage: %v", err)
	}
	certmagic.Default.Storage = cs

	// Set the AltTLSALPNPort so the solver won't start another listener
	_, port, err := net.SplitHostPort(config.ListenAddr)
	if err != nil {
		return nil, err
	}
	tlsALPNPort, err := net.LookupPort("tcp", port)
	if err != nil {
		return nil, err
	}
	certmagic.DefaultACME.AltTLSALPNPort = tlsALPNPort
	certmagic.DefaultACME.Email = config.CertMagicEmail

	if config.CertMagicStaging {
		certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA
	}

	certmagic.Default.Logger = log
	tlsConfig, err := certmagic.TLS(config.PublicURL)
	if err != nil {
		return nil, err
	}
	tlsConfig.NextProtos = append([]string{"h2", "http/1.1"}, tlsConfig.NextProtos...)
	return tlsConfig, nil
}
