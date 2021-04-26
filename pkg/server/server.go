// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"

	"github.com/gorilla/mux"
	minio "github.com/storj/minio/cmd"
	"github.com/storj/minio/pkg/storj/middleware/signature"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"gopkg.in/webhelp.v1/whlog"

	"storj.io/common/errs2"
	"storj.io/common/rpc/rpcpool"
	"storj.io/common/useragent"
	"storj.io/gateway-mt/pkg/server/middleware"
	"storj.io/private/version"
	"storj.io/uplink"
	"storj.io/uplink/private/transport"
)

var (
	// Error is an error class for internal Multinode Dashboard http server error.
	Error = errs.Class("gateway")
)

// Server represents an S3 compatible http server.
type Server struct {
	http         http.Server
	listener     net.Listener
	log          *zap.Logger
	Address      string
	DomainNames  []string
	RPCPool      *rpcpool.Pool
	AuthClient   *AuthClient
	UplinkConfig *uplink.Config
}

// New returns new instance of an S3 compatible http server.
func New(listener net.Listener, log *zap.Logger, tlsConfig *tls.Config, address string, domainNames []string) *Server {
	r := mux.NewRouter()
	r.SkipClean(true)

	s := &Server{listener: listener, log: log, http: http.Server{Handler: r, Addr: address}}

	if tlsConfig != nil {
		s.listener = tls.NewListener(listener, tlsConfig)
		s.http.TLSConfig = tlsConfig
	}

	publicServices := r.PathPrefix("/-/").Subrouter()
	publicServices.HandleFunc("/health", s.healthCheck)

	for _, domainName := range domainNames {
		pathStyle := r.Host(domainName).Subrouter()
		s.AddRoutes(pathStyle, "/{bucket:.+}", "/{bucket:.+}/{key:.+}")
		pathStyle.HandleFunc("/", s.ListBuckets).Methods(http.MethodGet)

		virtualHostStyle := r.Host("{bucket:.+}." + domainName).Subrouter()
		s.AddRoutes(virtualHostStyle, "/", "/{key:.+}")
	}

	// Gorilla matches in the order things are defined, so fall back
	// to minio implementations if we haven't handled something
	minio.RegisterAPIRouter(r)
	r.Use(middleware.Metrics)
	r.Use(minio.RegisterMiddlewares)

	s.http.Handler = minio.CriticalErrorHandler{
		Handler: minio.CorsHandler(r),
	}

	s.http.Handler = whlog.LogRequests(s.log.Sugar().Infof, s.http.Handler)
	s.http.Handler = whlog.LogResponses(s.log.Sugar().Infof, s.http.Handler)

	return s
}

func (s *Server) healthCheck(w http.ResponseWriter, r *http.Request) {
	// TODO: should this function do any tests to confirm the server is operational before returning a 200?
	// this function should be low-effort, in the sense that the load balancer is going to be hitting it regularly.
	w.WriteHeader(http.StatusOK)
}

// AddRoutes adds handlers to path-style and virtual-host style routes.
func (s *Server) AddRoutes(r *mux.Router, bucketPath, objectPath string) {
	// these routes were tested, but we have them commented out because they're currently not implemented
	// when implementing one of these, please also uncomment its test in server_test.go
	// r.HandleFunc(objectPath, s.DeleteObjectTagging).Methods(http.MethodDelete).Queries("tagging", "")
	// r.HandleFunc(objectPath, s.GetObjectTagging).Methods(http.MethodGet).Queries("tagging", "")
	// r.HandleFunc(objectPath, s.PutObjectTagging).Methods(http.MethodPut).Queries("tagging", "")

	// r.HandleFunc(objectPath, s.AbortMultipartUpload).Methods(http.MethodDelete).Queries("uploadId", "{UploadId:.+}")
	// r.HandleFunc(objectPath, s.ListParts).Methods(http.MethodGet).Queries("uploadId", "{UploadId:.+}")
	// r.HandleFunc(objectPath, s.CreateMultipartUpload).Methods(http.MethodPost).Queries("uploads", "")
	// r.HandleFunc(objectPath, s.CompleteMultipartUpload).Methods(http.MethodPost).Queries("uploadId", "{UploadId:.+}")
	// r.HandleFunc(objectPath, s.UploadPartCopy).Methods(http.MethodPut).Queries("uploadId", "{UploadId:.+}", "partNumber", "{partNumber:.+}").HeadersRegexp("x-amz-copy-source", ".+")
	// r.HandleFunc(objectPath, s.UploadPart).Methods(http.MethodPut).Queries("uploadId", "{UploadId:.+}", "partNumber", "{partNumber:.+}")

	// r.HandleFunc(objectPath, s.GetObject).Methods(http.MethodGet)
	// r.HandleFunc(objectPath, s.CopyObject).Methods(http.MethodPut).HeadersRegexp("x-amz-copy-source", ".+")
	// r.HandleFunc(objectPath, s.PutObject).Methods(http.MethodPut)
	// r.HandleFunc(objectPath, s.DeleteObject).Methods(http.MethodDelete)
	// r.HandleFunc(objectPath, s.HeadObject).Methods(http.MethodHead)

	// r.HandleFunc(bucketPath, s.DeleteBucketTagging).Methods(http.MethodDelete).Queries("tagging", "")
	// r.HandleFunc(bucketPath, s.GetBucketTagging).Methods(http.MethodGet).Queries("tagging", "")
	// r.HandleFunc(bucketPath, s.PutBucketTagging).Methods(http.MethodPut).Queries("tagging", "")
	r.HandleFunc(bucketPath, s.GetBucketVersioning).Methods(http.MethodGet).Queries("versioning", "")

	// r.HandleFunc(bucketPath, s.DeleteObjects).Methods(http.MethodPost).Queries("delete", "")
	// r.HandleFunc(bucketPath, s.ListMultipartUploads).Methods(http.MethodGet).Queries("uploads", "")
	// r.HandleFunc(bucketPath, s.ListObjectsV2).Methods(http.MethodGet).Queries("list-type", "2")
	// r.HandleFunc(bucketPath, s.ListObjects).Methods(http.MethodGet)
	// r.HandleFunc(bucketPath, s.CreateBucket).Methods(http.MethodPut)
	// r.HandleFunc(bucketPath, s.DeleteBucket).Methods(http.MethodDelete)
	// r.HandleFunc(bucketPath, s.HeadBucket).Methods(http.MethodHead)
}

// Run starts the S3 compatible http server.
func (s *Server) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	var group errgroup.Group
	group.Go(func() error {
		<-ctx.Done()
		return Error.Wrap(s.http.Shutdown(context.Background()))
	})
	group.Go(func() error {
		defer cancel()
		err := s.http.Serve(s.listener)
		if errs2.IsCanceled(err) || errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		return Error.Wrap(err)
	})
	return group.Wait()
}

// Close closes server and underlying listener.
func (s *Server) Close() error {
	return Error.Wrap(s.http.Close())
}

// WithProject handles opening and closing a project within a request handler.
func (s *Server) WithProject(w http.ResponseWriter, r *http.Request, h func(context.Context, *uplink.Project) error) {
	ctx := r.Context()
	creds := signature.GetCredentials(ctx)
	authAccess, err := s.AuthClient.GetAccess(ctx, creds.AccessKeyID)
	if err != nil {
		s.WriteError(ctx, w, err, r.URL)
		return
	}
	accessGrant, err := uplink.ParseAccess(authAccess.AccessGrant)
	if err != nil {
		s.WriteError(ctx, w, err, r.URL)
		return
	}
	uplinkConfig := s.UplinkConfig
	uplinkConfig.UserAgent = getUserAgent(r.UserAgent())
	err = transport.SetConnectionPool(ctx, s.UplinkConfig, s.RPCPool)
	if err != nil {
		s.WriteError(ctx, w, err, r.URL)
		return
	}

	project, err := uplinkConfig.OpenProject(ctx, accessGrant)
	if err != nil {
		s.WriteError(ctx, w, err, r.URL)
		return
	}
	defer func() {
		if err := project.Close(); err != nil {
			s.log.Warn("Failed to close project", zap.Error(err))
		}
	}()
	err = h(ctx, project)
	if err != nil {
		s.WriteError(ctx, w, err, r.URL)
		return
	}
}

var gatewayUserAgent = "Gateway-MT/" + version.Build.Version.String()

func getUserAgent(clientAgent string) string {
	if clientAgent == "" {
		return gatewayUserAgent
	}
	_, err := useragent.ParseEntries([]byte(clientAgent))
	if err != nil {
		return gatewayUserAgent
	}
	return gatewayUserAgent + " " + clientAgent
}
