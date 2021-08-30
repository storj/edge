// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.
package drpcauth

import (
	"context"
	"net/url"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/pb"
	"storj.io/common/storj"
	"storj.io/common/testcontext"
	"storj.io/gateway-mt/auth/authdb"
	"storj.io/gateway-mt/auth/memauth"
)

const minimalAccess = "13J4Upun87ATb3T5T5sDXVeQaCzWFZeF9Ly4ELfxS5hUwTL8APEkwahTEJ1wxZjyErimiDs3kgid33kDLuYPYtwaY7Toy32mCTapfrUB814X13RiA844HPWK3QLKZb9cAoVceTowmNZXWbcUMKNbkMHCURE4hn8ZrdHPE3S86yngjvDxwKmarfGx"

// This is the satellite address embedded in the access above.
const minimalAccessSatelliteURL = "1SYXsAycDPUu4z2ZksJD5fh5nTDcH3vCFHnpcVye5XuL1NrYV@s"

var minimalAccessSatelliteID = func() storj.NodeID {
	url, err := storj.ParseNodeURL(minimalAccessSatelliteURL)
	if err != nil {
		panic(err)
	}

	return url.ID
}()

func createBackend(ctx context.Context, t *testing.T) (*GatewayAuthServer, *authdb.Database) {
	endpoint, err := url.Parse("http://best-gateway.com/")
	require.NoError(t, err)
	allowedSatelliteIDs := map[storj.NodeID]struct{}{minimalAccessSatelliteID: {}}

	db := authdb.NewDatabase(memauth.New(), allowedSatelliteIDs)

	return NewGatewayAuthServer(ctx, zaptest.NewLogger(t), db, endpoint), db
}

func TestRegisterGatewayAccess(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()
	server, db := createBackend(ctx, t)

	binaryAccessGrant, _, err := base58.CheckDecode(minimalAccess)
	require.NoError(t, err)

	response, err := server.RegisterGatewayAccess(
		ctx,
		&pb.RegisterGatewayAccessRequest{
			AccessGrant: binaryAccessGrant,
			Public:      false,
		},
	)
	require.NoError(t, err)
	require.Equal(t, "http://best-gateway.com/", response.Endpoint)
	require.Len(t, response.AccessKeyId, 17)
	require.Len(t, response.SecretKey, 33)

	var accessKeyID authdb.EncryptionKey

	err = accessKeyID.FromBinary(response.AccessKeyId)
	require.NoError(t, err)

	storedAccessGrant, storedPublic, storedSecretKey, err := db.Get(
		ctx,
		accessKeyID,
	)

	require.NoError(t, err)
	require.Equal(t, false, storedPublic)
	require.Equal(t, minimalAccess, storedAccessGrant)
	require.Equal(t, response.SecretKey, storedSecretKey.ToBinary())
}
