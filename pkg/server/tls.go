// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"crypto/tls"
	"os"
	"path/filepath"

	"github.com/zeebo/errs"
)

// BaseTLSConfig returns a tls.Config with some good default settings for security.
func BaseTLSConfig() *tls.Config {
	// these settings give us a score of A on https://www.ssllabs.com/ssltest/index.html
	return &tls.Config{
		MinVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: true, // thanks, jeff hodges! https://groups.google.com/g/golang-nuts/c/m3l0AesTdog/m/8CeLeVVyWw4J
	}
}

// LoadTLSConfigFromDir reads a directory and loads certificates it contains.
func LoadTLSConfigFromDir(configDir string) (*tls.Config, error) {
	certFiles, err := filepath.Glob(filepath.Join(configDir, "*.crt"))
	if err != nil {
		return nil, errs.New("Error reading for certificate directory '%s'", certFiles)
	}
	certificates := []tls.Certificate{}
	for _, crt := range certFiles {
		key := crt[0:len(crt)-4] + ".key"
		_, err := os.Stat(key)
		if err != nil {
			return nil, errs.New("unable to locate key for cert %s (expecting %s): %v", crt, key, err)
		}

		cert, err := tls.LoadX509KeyPair(crt, key)
		if err != nil {
			return nil, errs.New("unable to load server keypair: %v", err)
		}
		certificates = append(certificates, cert)
	}
	tlsConfig := BaseTLSConfig()
	tlsConfig.Certificates = certificates
	return tlsConfig, nil
}
