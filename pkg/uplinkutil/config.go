// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package uplinkutil

import (
	"os"

	"github.com/zeebo/errs"
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
