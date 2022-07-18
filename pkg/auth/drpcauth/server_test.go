// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.
package drpcauth

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/memory"
	"storj.io/common/pb"
	"storj.io/common/rpc/rpcstatus"
	"storj.io/common/storj"
	"storj.io/common/testcontext"
	"storj.io/gateway-mt/pkg/auth/authdb"
	"storj.io/gateway-mt/pkg/auth/memauth"
)

const minimalAccess = "13J4Upun87ATb3T5T5sDXVeQaCzWFZeF9Ly4ELfxS5hUwTL8APEkwahTEJ1wxZjyErimiDs3kgid33kDLuYPYtwaY7Toy32mCTapfrUB814X13RiA844HPWK3QLKZb9cAoVceTowmNZXWbcUMKNbkMHCURE4hn8ZrdHPE3S86yngjvDxwKmarfGx"

// This is the satellite address embedded in the access above.
const minimalAccessSatelliteURL = "1SYXsAycDPUu4z2ZksJD5fh5nTDcH3vCFHnpcVye5XuL1NrYV@s"

var minimalAccessSatelliteID = func() storj.NodeURL {
	url, err := storj.ParseNodeURL(minimalAccessSatelliteURL)
	if err != nil {
		panic(err)
	}

	return url
}()

func createBackend(t *testing.T, sizeLimit memory.Size) (*Server, *authdb.Database) {
	endpoint, err := url.Parse("http://gateway.test")
	require.NoError(t, err)
	allowedSatelliteIDs := map[storj.NodeURL]struct{}{minimalAccessSatelliteID: {}}

	db := authdb.NewDatabase(memauth.New(), allowedSatelliteIDs)

	return NewServer(zaptest.NewLogger(t), db, endpoint, sizeLimit), db
}

func TestRegisterAccess(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	server, db := createBackend(t, 4*memory.KiB)

	response, err := server.RegisterAccess(
		ctx,
		&pb.EdgeRegisterAccessRequest{
			AccessGrant: minimalAccess,
			Public:      false,
		},
	)
	require.NoError(t, err)
	require.Equal(t, "http://gateway.test", response.Endpoint)
	require.Len(t, response.AccessKeyId, 28)
	require.Len(t, response.SecretKey, 53)

	var accessKeyID authdb.EncryptionKey

	err = accessKeyID.FromBase32(response.AccessKeyId)
	require.NoError(t, err)

	storedAccessGrant, storedPublic, storedSecretKey, err := db.Get(
		ctx,
		accessKeyID,
	)

	require.NoError(t, err)
	require.Equal(t, false, storedPublic)
	require.Equal(t, minimalAccess, storedAccessGrant)
	require.Equal(t, response.SecretKey, storedSecretKey.ToBase32())
}

func TestRegisterAccessTooLarge(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	server, _ := createBackend(t, memory.Size(len(minimalAccess)))

	_, err := server.RegisterAccess(
		ctx,
		&pb.EdgeRegisterAccessRequest{
			AccessGrant: minimalAccess + "a",
			Public:      false,
		},
	)
	require.Error(t, err)

	assert.Equal(t, rpcstatus.InvalidArgument, rpcstatus.Code(err))
	assert.EqualError(t, err, "provided access grant is too large")

	_, err = server.RegisterAccess(
		ctx,
		&pb.EdgeRegisterAccessRequest{
			AccessGrant: minimalAccess,
			Public:      false,
		},
	)
	require.NoError(t, err)
}
