// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package drpcauth

import (
	"context"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeebo/errs"
	"go.uber.org/zap/zaptest"

	"storj.io/common/memory"
	"storj.io/common/pb"
	"storj.io/common/rpc/rpcstatus"
	"storj.io/common/storj"
	"storj.io/common/testcontext"
	"storj.io/edge/pkg/auth/authdb"
	"storj.io/edge/pkg/auth/badgerauth"
	"storj.io/edge/pkg/auth/spannerauth"
	"storj.io/edge/pkg/auth/spannerauth/spannerauthtest"
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

func createBackend(t *testing.T, sizeLimit memory.Size) (_ *Server, _ *authdb.Database, close func() error) {
	logger := zaptest.NewLogger(t)

	storage, err := badgerauth.Open(logger, badgerauth.Config{FirstStart: true})
	require.NoError(t, err)

	db, err := authdb.NewDatabase(zaptest.NewLogger(t), storage, authdb.Config{
		AllowedSatelliteURLs: map[storj.NodeURL]struct{}{minimalAccessSatelliteID: {}},
	})
	require.NoError(t, err)

	endpoint, err := url.Parse("http://gateway.test")
	require.NoError(t, err)

	return NewServer(logger, db, endpoint, sizeLimit), db, func() error {
		return errs.Combine(storage.Close(), logger.Sync())
	}
}

func TestRegisterAccess(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	server, db, close := createBackend(t, 4*memory.KiB)
	defer ctx.Check(close)

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

	result, err := db.Get(ctx, accessKeyID)

	require.NoError(t, err)
	require.Equal(t, false, result.Public)
	require.Equal(t, minimalAccess, result.AccessGrant)
	require.Equal(t, response.SecretKey, result.SecretKey.ToBase32())
}

func TestRegisterAccessContextCanceled(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	logger := zaptest.NewLogger(t)
	defer ctx.Check(logger.Sync)

	spannerServer, err := spannerauthtest.ConfigureTestServer(ctx, logger)
	require.NoError(t, err)
	defer spannerServer.Close()

	storage, err := spannerauth.Open(ctx, logger, spannerauth.Config{
		DatabaseName: "projects/P/instances/I/databases/D",
		Address:      spannerServer.Addr,
	})
	require.NoError(t, err)
	defer ctx.Check(storage.Close)

	require.NoError(t, storage.HealthCheck(ctx))

	db, err := authdb.NewDatabase(zaptest.NewLogger(t), storage, authdb.Config{
		AllowedSatelliteURLs: map[storj.NodeURL]struct{}{minimalAccessSatelliteID: {}},
	})
	require.NoError(t, err)

	endpoint, err := url.Parse("http://gateway.test")
	require.NoError(t, err)

	server := NewServer(logger, db, endpoint, 4*memory.KiB)

	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()

	response, err := server.RegisterAccess(
		canceledCtx,
		&pb.EdgeRegisterAccessRequest{
			AccessGrant: minimalAccess,
			Public:      false,
		},
	)
	require.Nil(t, response)
	require.EqualError(t, err, rpcstatus.Error(rpcstatus.Canceled, "").Error())
}

func TestRegisterAccessTooLarge(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	server, _, close := createBackend(t, memory.Size(len(minimalAccess)))
	defer ctx.Check(close)

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
