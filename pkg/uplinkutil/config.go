// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package uplinkutil

import (
	"os"
	"strings"

	"github.com/zeebo/errs"

	"storj.io/common/identity"
)

// IdentityConfig is an intentional copy of identity.Config that has
// empty defaults.
type IdentityConfig struct {
	CertPath string `help:"path to the certificate chain for this identity" default:"" user:"true" path:"true"`
	KeyPath  string `help:"path to the private key for this identity" default:"" user:"true" path:"true"`
}

// LoadPEMs loads files and returns their byte strings if set. A possible
// return value of this function is nil, nil, nil.
func (c *IdentityConfig) LoadPEMs() (certPEM, keyPEM []byte, err error) {
	if c.CertPath == "" && c.KeyPath == "" {
		return nil, nil, nil
	}
	if c.CertPath == "" || c.KeyPath == "" {
		return nil, nil, errs.New("only one of key path and cert path are set (%q, %q)", c.KeyPath, c.CertPath)
	}
	certPEM, err = os.ReadFile(c.CertPath)
	if err != nil {
		return nil, nil, errs.New("failed reading cert path %q: %+v", c.CertPath, err)
	}
	keyPEM, err = os.ReadFile(c.KeyPath)
	if err != nil {
		return nil, nil, errs.New("failed reading key path %q: %+v", c.KeyPath, err)
	}
	return certPEM, keyPEM, nil
}

// IdentitiesConfig is a way of specifying multiple identities.
type IdentitiesConfig struct {
	CertPaths string `help:"a comma separated list of certificate chains. must be in the same order as the key-paths list." default:"" user:"true"`
	KeyPaths  string `help:"a comma separated list of private key files. must be in the same order as the cert-paths list." default:"" user:"true"`
}

// LoadIdentities loads a list of identity.FullIdentities from a config.
func (c *IdentitiesConfig) LoadIdentities() (identities []*identity.FullIdentity, err error) {
	if c.CertPaths == "" && c.KeyPaths == "" {
		return nil, nil
	}
	certPaths := strings.Split(c.CertPaths, ",")
	keyPaths := strings.Split(c.KeyPaths, ",")
	if len(keyPaths) != len(certPaths) {
		return nil, errs.New("mismatched number of key paths and cert paths")
	}
	for i := range keyPaths {
		keyPEM, err := os.ReadFile(keyPaths[i])
		if err != nil {
			return nil, errs.New("Failed to open %q: %w", keyPaths[i], err)
		}
		certPEM, err := os.ReadFile(certPaths[i])
		if err != nil {
			return nil, errs.New("Failed to open %q: %w", certPaths[i], err)
		}
		identity, err := identity.FullIdentityFromPEM(certPEM, keyPEM)
		if err != nil {
			return nil, errs.New("failed to use %q, %q: %w", keyPaths[i], certPaths[i], err)
		}
		identities = append(identities, identity)
	}
	return identities, nil
}
