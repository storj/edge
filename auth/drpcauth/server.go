// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

// Package drpcauth implements the same functionality as package httpauth
// but with DRPC as transport.
//
// This way the Auth service can be called with libuplink
// without requiring a HTTP client as a dependency.
//
// Currently no authentication is required for this functionality.
package drpcauth

import (
	"context"
	"net"
	"net/url"

	"github.com/btcsuite/btcutil/base58"
	"go.uber.org/zap"

	"storj.io/common/pb"
	"storj.io/common/rpc/rpcstatus"
	"storj.io/drpc/drpcmux"
	"storj.io/drpc/drpcserver"
	"storj.io/gateway-mt/auth/authdb"
)

// GatewayAuthServer is a collection of dependencies for the DRPC-based service
// It is an interface for clients like Uplink to use the auth service.
type GatewayAuthServer struct {
	pb.DRPCGatewayAuthServer

	ctx context.Context
	log *zap.Logger

	// This is duplicated with package storj.io/gateway-mt/auth/httpauth/resources
	// TODO: factor out common functionality
	db       *authdb.Database
	endpoint *url.URL
}

// NewGatewayAuthServer creates a GatewayAuthServer which is not running.
func NewGatewayAuthServer(
	ctx context.Context,
	log *zap.Logger,
	db *authdb.Database,
	endpoint *url.URL,
) *GatewayAuthServer {
	return &GatewayAuthServer{
		ctx:      ctx,
		log:      log,
		db:       db,
		endpoint: endpoint,
	}
}

// RegisterGatewayAccess implements interface DRPCGatewayAuthServer.
// Wraps the actual functionality with logging.
func (g *GatewayAuthServer) RegisterGatewayAccess(
	ctx context.Context,
	request *pb.RegisterGatewayAccessRequest,
) (*pb.RegisterGatewayAccessResponse, error) {
	g.log.Debug("DRPC RegisterGatewayAccess request")

	response, err := g.registerGatewayAccessImpl(ctx, request)

	if err != nil {
		g.log.Error("DRPC RegisterGatewayAccess failed", zap.Error(err))
		err = rpcstatus.Wrap(rpcstatus.Internal, err)
	} else {
		g.log.Debug("DRPC RegisterGatewayAccess success")
	}

	return response, err
}

func (g *GatewayAuthServer) registerGatewayAccessImpl(
	ctx context.Context,
	request *pb.RegisterGatewayAccessRequest,
) (*pb.RegisterGatewayAccessResponse, error) {
	accessKey, err := authdb.NewEncryptionKey()
	if err != nil {
		return nil, err
	}

	secretKey, err := g.db.Put(ctx, accessKey, base58.CheckEncode(request.AccessGrant, 0), request.Public)
	if err != nil {
		return nil, err
	}

	response := pb.RegisterGatewayAccessResponse{
		AccessKeyId: accessKey.ToBinary(),
		SecretKey:   secretKey.ToBinary(),
		Endpoint:    g.endpoint.String(),
	}

	return &response, nil
}

// StartListen start a DRPC server on the given listener.
func StartListen(
	ctx context.Context,
	gatewayAuthServer pb.DRPCGatewayAuthServer,
	listener net.Listener,
) error {
	mux := drpcmux.New()

	err := pb.DRPCRegisterGatewayAuth(mux, gatewayAuthServer)
	if err != nil {
		return err
	}

	server := drpcserver.New(mux)

	return server.Serve(ctx, listener)
}
