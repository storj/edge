// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauth

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"

	"github.com/zeebo/errs"
)

// TLSError is an error class for tls setup problems.
var TLSError = errs.Class("tls")

// TLSOptions contains configuration for tls.
type TLSOptions struct {
	// CertsDir defines a folder for loading the certificates.
	// The filenames follow this convention:
	//
	//    node.crt, node.key: define certificate and private key
	//    ca.crt: defines certificate authority for other peers.
	CertsDir string
}

// Load loads the certificates and configuration specified by the options.
func (opts TLSOptions) Load() (*tls.Config, error) {
	config := &tls.Config{
		// pool for CA-s
		RootCAs: x509.NewCertPool(),
		// certificates we use ourselves
		Certificates: []tls.Certificate{},
		// require clients to authenticate
		ClientAuth: tls.RequireAndVerifyClientCert,
		// pool for client certificate authorities
		ClientCAs: x509.NewCertPool(),
		// verify client certs
		VerifyPeerCertificate: nil,
	}

	entries, err := os.ReadDir(opts.CertsDir)
	if err != nil {
		return nil, TLSError.New("failed to read certs dir %q: %w", opts.CertsDir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) != ".crt" {
			continue
		}

		parts := strings.Split(entry.Name(), ".")
		if len(parts) < 2 {
			return nil, TLSError.New("misnamed certificate %q", entry.Name())
		}
		full := filepath.Join(opts.CertsDir, entry.Name())

		switch parts[0] {
		case "ca":
			pem, err := os.ReadFile(full)
			if err != nil {
				return nil, TLSError.New("failed to read %q: %w", entry.Name(), err)
			}
			if !config.RootCAs.AppendCertsFromPEM(pem) {
				return nil, TLSError.New("failed to add %q", entry.Name())
			}
			if !config.ClientCAs.AppendCertsFromPEM(pem) {
				return nil, TLSError.New("failed to add %q", entry.Name())
			}

		case "node", "client":
			keypair, err := tls.LoadX509KeyPair(full, changeExt(full, ".key"))
			if err != nil {
				return nil, TLSError.New("failed to load node keypair %q", entry.Name())
			}
			config.Certificates = append(config.Certificates, keypair)
		default:
			return nil, TLSError.New("don't know how to handle %q", entry.Name())
		}
	}

	return config, nil
}

func changeExt(path, newext string) string {
	ext := filepath.Ext(path)
	return path[:len(path)-len(ext)] + newext
}
