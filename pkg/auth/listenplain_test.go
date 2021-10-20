// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package auth

import (
	"context"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/pb"
	"storj.io/common/rpc"
	"storj.io/common/testcontext"
)

func TestPlain(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	serverCtx, serverCancel := context.WithCancel(ctx)
	defer serverCancel()

	type MockHTTPHandler struct {
		http.Handler
	}

	httpServer := &http.Server{
		Handler: MockHTTPHandler{},
	}
	defer func() {
		err := httpServer.Close()
		require.NoError(t, err)
	}()

	ctx.Go(func() error {
		return listenAndServePlain(
			serverCtx,
			zaptest.NewLogger(t),
			listener,
			&DRPCServerMock{},
			httpServer,
		)
	})

	dialer := rpc.NewDefaultDialer(nil)

	connection, err := dialer.DialAddressUnencrypted(ctx, listener.Addr().String())
	require.NoError(t, err)

	drpcClient := pb.NewDRPCEdgeAuthClient(connection)

	accessGrant := "1JdRhtpnQUH3KggvmzfMhUT9pDTF9L8CFZoU5NynjRmaVQ4mCev6ZAGiPrpTem5PcfEEFTRioDk4eed2uJADVAvtSH3ETdbokBy7o3355ih9rJ2j5h8vC9yrVrdRjnAdwvaEJADJJTbL8VqZT6Jksd5tP6roMQbwZog9RNoSKMjb71Z9TAG1dTGLfqpBV5nsktyZaGdsru32Wk7BCvNQV3VdgPmax6AGPdnv4WNBrzmLVNQzhpHGx9LsKzfECtQMQTdrmULgqUiJBFoUafB"

	registerAccessResponse, err := drpcClient.RegisterAccess(ctx, &pb.EdgeRegisterAccessRequest{
		AccessGrant: accessGrant,
		Public:      false,
	})
	require.NoError(t, err)

	require.Equal(t, "accesskeyid", registerAccessResponse.AccessKeyId)
	require.Equal(t, "secretkey", registerAccessResponse.SecretKey)
	require.Equal(t, "endpoint", registerAccessResponse.Endpoint)
}
