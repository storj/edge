// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauth_test

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/require"

	"storj.io/common/testcontext"
	"storj.io/gateway-mt/pkg/auth/badgerauth"
	"storj.io/gateway-mt/pkg/auth/badgerauth/badgerauthtest"
)

func TestServer(t *testing.T) {
	badgerauthtest.RunSingleNode(t, badgerauth.Config{}, func(ctx *testcontext.Context, t *testing.T, node *badgerauth.Node) {
		t.Log("started")
	})
}

func TestServerCerts(t *testing.T) {
	certsctx := testcontext.New(t)
	trusted := createTestingPool(t, 1)

	err := ioutil.WriteFile(certsctx.File("ca.crt"), encodeCertificate(trusted.CA.Raw), 0644)
	require.NoError(t, err)
	err = ioutil.WriteFile(certsctx.File("node.crt"), encodeCertificate(trusted.Certs[0].Certificate[0]), 0644)
	require.NoError(t, err)
	err = ioutil.WriteFile(certsctx.File("node.key"), encodePrivateKey(trusted.Certs[0].PrivateKey), 0644)
	require.NoError(t, err)

	badgerauthtest.RunSingleNode(t, badgerauth.Config{
		CertsDir: certsctx.Dir(),
	}, func(ctx *testcontext.Context, t *testing.T, node *badgerauth.Node) {
		t.Log("started")
	})
}
