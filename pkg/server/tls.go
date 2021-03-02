// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"crypto/tls"
	"os"
	"path/filepath"

	"github.com/zeebo/errs"
)

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
	return &tls.Config{Certificates: certificates}, nil
}
