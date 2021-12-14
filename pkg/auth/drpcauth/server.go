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

	"github.com/spacemonkeygo/monkit/v3"
	"go.uber.org/zap"

	"storj.io/common/pb"
	"storj.io/common/rpc/rpcstatus"
	"storj.io/drpc/drpcmux"
	"storj.io/drpc/drpcserver"
	"storj.io/gateway-mt/pkg/auth/authdb"
)

var mon = monkit.Package()

// Server is a collection of dependencies for the DRPC-based service
// It is an interface for clients like Uplink to use the auth service.
type Server struct {
	pb.DRPCEdgeAuthServer

	log *zap.Logger

	// This is duplicated with package storj.io/gateway-mt/pkg/auth/httpauth/resources
	// TODO: factor out common functionality
	db       *authdb.Database
	endpoint *url.URL
}

// NewServer creates a Server that is not running.
func NewServer(
	log *zap.Logger,
	db *authdb.Database,
	endpoint *url.URL,
) *Server {
	return &Server{
		log:      log,
		db:       db,
		endpoint: endpoint,
	}
}

// RegisterAccess implements interface DRPCEdgeAuthServer.
// Wraps the actual functionality with logging.
func (g *Server) RegisterAccess(
	ctx context.Context,
	request *pb.EdgeRegisterAccessRequest,
) (_ *pb.EdgeRegisterAccessResponse, err error) {
	defer mon.Task()(&ctx)(&err)

	g.log.Debug("DRPC RegisterAccess request")

	response, err := g.registerAccessImpl(ctx, request)

	if err != nil {
		g.log.Error("DRPC RegisterAccess failed", zap.Error(err))
		err = rpcstatus.Wrap(rpcstatus.Internal, err)
	} else {
		g.log.Debug("DRPC RegisterAccess success")
	}

	return response, err
}

func (g *Server) registerAccessImpl(
	ctx context.Context,
	request *pb.EdgeRegisterAccessRequest,
) (_ *pb.EdgeRegisterAccessResponse, err error) {
	defer mon.Task()(&ctx)(&err)

	accessKey, err := authdb.NewEncryptionKey()
	if err != nil {
		return nil, err
	}

	secretKey, err := g.db.Put(ctx, accessKey, request.AccessGrant, request.Public)
	if err != nil {
		return nil, err
	}

	response := pb.EdgeRegisterAccessResponse{
		AccessKeyId: accessKey.ToBase32(),
		SecretKey:   secretKey.ToBase32(),
		Endpoint:    g.endpoint.String(),
	}

	return &response, nil
}

// StartListen start a DRPC server on the given listener.
func StartListen(
	ctx context.Context,
	authServer pb.DRPCEdgeAuthServer,
	listener net.Listener,
) (err error) {
	defer mon.Task()(&ctx)(&err)

	mux := drpcmux.New()

	if err = pb.DRPCRegisterEdgeAuth(mux, authServer); err != nil {
		return err
	}

	server := drpcserver.New(mux)

	return server.Serve(ctx, listener)
}
