// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"

	miniogo "github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/tags"
	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"

	"storj.io/common/errs2"
	"storj.io/common/rpc/rpcpool"
	"storj.io/common/useragent"
	"storj.io/gateway-mt/pkg/server/gwlog"
	"storj.io/gateway-mt/pkg/server/middleware"
	"storj.io/gateway/miniogw"
	minio "storj.io/minio/cmd"
	"storj.io/minio/cmd/logger"
	"storj.io/minio/pkg/auth"
	"storj.io/private/version"
	"storj.io/uplink"
	"storj.io/uplink/private/transport"
)

var (
	mon = monkit.Package()

	gatewayUserAgent = "Gateway-MT/" + version.Build.Version.String()

	// ErrAccessGrant occurs when failing to parse the access grant from the
	// request.
	ErrAccessGrant = errs.Class("access grant")

	// ErrAccessKeyEmpty occurs when no access key could be found in the request.
	ErrAccessKeyEmpty = miniogo.ErrorResponse{
		Code:       "XStorjAccessKeyEmpty",
		StatusCode: http.StatusUnauthorized,
		Message:    "Access key is empty.",
	}
)

type multiTenantGateway struct {
	gateway        minio.Gateway
	connectionPool *rpcpool.Pool

	config         uplink.Config
	insecureLogAll bool
}

// NewMultiTenantGateway returns a wrapper of minio.Gateway that logs responses
// and makes gateway multi-tenant. The properly closed (Shutdown method) object
// layer of the returned minio.Gateway will also close connectionPool.
func NewMultiTenantGateway(gateway minio.Gateway, connectionPool *rpcpool.Pool, config uplink.Config, insecureLogAll bool) minio.Gateway {
	return &multiTenantGateway{
		gateway:        gateway,
		connectionPool: connectionPool,
		config:         config,
		insecureLogAll: insecureLogAll,
	}
}

func (g *multiTenantGateway) Name() string { return g.gateway.Name() }

func (g *multiTenantGateway) NewGatewayLayer(creds auth.Credentials) (minio.ObjectLayer, error) {
	layer, err := g.gateway.NewGatewayLayer(creds)

	return &multiTenancyLayer{
		layer:          layer,
		connectionPool: g.connectionPool,
		config:         g.config,
		insecureLogAll: g.insecureLogAll,
	}, err
}

func (g *multiTenantGateway) Production() bool { return g.gateway.Production() }

type multiTenancyLayer struct {
	minio.GatewayUnsupported

	layer          minio.ObjectLayer
	connectionPool *rpcpool.Pool

	config         uplink.Config
	insecureLogAll bool
}

// minioError checks if the given error is a minio error.
func minioError(err error) bool {
	// some minio errors are not minio.GenericError, so we need to check for
	// these specifically.
	switch {
	case errors.As(err, &miniogo.ErrorResponse{}):
		return true
	default:
		return reflect.TypeOf(err).ConvertibleTo(reflect.TypeOf(minio.GenericError{}))
	}
}

// log all errors and relevant request information.
func (l *multiTenancyLayer) log(ctx context.Context, err error) error {
	reqInfo := logger.GetReqInfo(ctx)
	if reqInfo == nil {
		return err
	}

	// log any unexpected errors, or log every error if flag set
	if err != nil && (l.insecureLogAll || (!minioError(err) && !(errs2.IsCanceled(ctx.Err()) || errs2.IsCanceled(err)))) {
		reqInfo.SetTags("error", err.Error())
	}

	// logger.GetReqInfo(ctx) will get the ReqInfo from context minio created as
	// a copy of the parent request context. Our logging/metrics middleware can
	// only see the parent context without the ReqInfo value, so in order for it
	// to get at the ReqInfo data, we copy it to a separate log value both this
	// gateway and our middleware can see, one that was set in context from the
	// middleware itself, and so is accessible here. The alternative to this was
	// to modify minio to avoid creating a ReqInfo and use the same reference of
	// a ReqInfo that was set in our middleware, but we want to avoid modifying
	// minio as much as we can help it.
	if log, ok := gwlog.FromContext(ctx); ok {
		copyReqInfo(log, reqInfo)
	}

	return err
}

func copyReqInfo(dst *gwlog.Log, src *logger.ReqInfo) {
	dst.RemoteHost = src.RemoteHost
	dst.Host = src.Host
	dst.UserAgent = src.UserAgent
	dst.DeploymentID = src.DeploymentID
	dst.RequestID = src.RequestID
	dst.API = src.API
	dst.BucketName = src.BucketName
	dst.ObjectName = src.ObjectName
	dst.AccessKey = src.AccessKey

	for _, tag := range src.GetTags() {
		dst.SetTags(tag.Key, tag.Val)
	}
}

func (l *multiTenancyLayer) Shutdown(ctx context.Context) error {
	return l.log(ctx, l.connectionPool.Close())
}

func (l *multiTenancyLayer) StorageInfo(ctx context.Context, local bool) (minio.StorageInfo, []error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.StorageInfo{}, []error{err}
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	info, errors := l.layer.StorageInfo(miniogw.WithUplinkProject(ctx, project), false)

	for _, err := range errors {
		_ = l.log(ctx, err)
	}

	return info, errors
}

func (l *multiTenancyLayer) MakeBucketWithLocation(ctx context.Context, bucket string, opts minio.BucketOptions) error {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	return l.log(ctx, l.layer.MakeBucketWithLocation(miniogw.WithUplinkProject(ctx, project), bucket, opts))
}

func (l *multiTenancyLayer) GetBucketInfo(ctx context.Context, bucket string) (bucketInfo minio.BucketInfo, err error) {
	accessGrant := getAccessGrant(ctx)

	// Some S3 (like AWS S3) implementations allow anonymous checks for bucket
	// existence, but we explicitly forbid those and return
	// `minio.NotImplemented`, which seems to be the most appropriate response
	// in this case.
	if accessGrant == "" {
		return minio.BucketInfo{}, minio.NotImplemented{API: "GetBucketInfo (anonymous)"}
	}

	project, err := l.openProject(ctx, accessGrant)
	if err != nil {
		return minio.BucketInfo{}, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	bucketInfo, err = l.layer.GetBucketInfo(miniogw.WithUplinkProject(ctx, project), bucket)
	return bucketInfo, l.log(ctx, err)
}

func (l *multiTenancyLayer) ListBuckets(ctx context.Context) (buckets []minio.BucketInfo, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return nil, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	buckets, err = l.layer.ListBuckets(miniogw.WithUplinkProject(ctx, project))
	return buckets, l.log(ctx, err)
}

func (l *multiTenancyLayer) DeleteBucket(ctx context.Context, bucket string, forceDelete bool) error {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	return l.log(ctx, l.layer.DeleteBucket(miniogw.WithUplinkProject(ctx, project), bucket, forceDelete))
}

func (l *multiTenancyLayer) ListObjects(ctx context.Context, bucket, prefix, marker, delimiter string, maxKeys int) (result minio.ListObjectsInfo, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.ListObjectsInfo{}, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	result, err = l.layer.ListObjects(miniogw.WithUplinkProject(ctx, project), bucket, prefix, marker, delimiter, maxKeys)
	return result, l.log(ctx, err)
}

func (l *multiTenancyLayer) ListObjectsV2(ctx context.Context, bucket, prefix, continuationToken, delimiter string, maxKeys int, fetchOwner bool, startAfter string) (result minio.ListObjectsV2Info, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.ListObjectsV2Info{}, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	result, err = l.layer.ListObjectsV2(miniogw.WithUplinkProject(ctx, project), bucket, prefix, continuationToken, delimiter, maxKeys, fetchOwner, startAfter)
	return result, l.log(ctx, err)
}

func (l *multiTenancyLayer) GetObjectNInfo(ctx context.Context, bucket, object string, rs *minio.HTTPRangeSpec, h http.Header, lockType minio.LockType, opts minio.ObjectOptions) (reader *minio.GetObjectReader, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return nil, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	reader, err = l.layer.GetObjectNInfo(miniogw.WithUplinkProject(ctx, project), bucket, object, rs, h, lockType, opts)
	return reader, l.log(ctx, err)
}

func (l *multiTenancyLayer) GetObject(ctx context.Context, bucket, object string, startOffset, length int64, writer io.Writer, etag string, opts minio.ObjectOptions) error {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	return l.log(ctx, l.layer.GetObject(miniogw.WithUplinkProject(ctx, project), bucket, object, startOffset, length, writer, etag, opts))
}

func (l *multiTenancyLayer) GetObjectInfo(ctx context.Context, bucket, object string, opts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.ObjectInfo{}, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	objInfo, err = l.layer.GetObjectInfo(miniogw.WithUplinkProject(ctx, project), bucket, object, opts)
	return objInfo, l.log(ctx, err)
}

func (l *multiTenancyLayer) PutObject(ctx context.Context, bucket, object string, data *minio.PutObjReader, opts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.ObjectInfo{}, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	objInfo, err = l.layer.PutObject(miniogw.WithUplinkProject(ctx, project), bucket, object, data, opts)

	return objInfo, l.log(ctx, err)
}

func (l *multiTenancyLayer) CopyObject(ctx context.Context, srcBucket, srcObject, destBucket, destObject string, srcInfo minio.ObjectInfo, srcOpts, destOpts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.ObjectInfo{}, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	objInfo, err = l.layer.CopyObject(miniogw.WithUplinkProject(ctx, project), srcBucket, srcObject, destBucket, destObject, srcInfo, srcOpts, destOpts)
	return objInfo, l.log(ctx, err)
}

func (l *multiTenancyLayer) DeleteObject(ctx context.Context, bucket, object string, opts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.ObjectInfo{}, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	objInfo, err = l.layer.DeleteObject(miniogw.WithUplinkProject(ctx, project), bucket, object, opts)
	return objInfo, l.log(ctx, err)
}

func (l *multiTenancyLayer) DeleteObjects(ctx context.Context, bucket string, objects []minio.ObjectToDelete, opts minio.ObjectOptions) (deleted []minio.DeletedObject, errors []error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return nil, []error{err}
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	deleted, errors = l.layer.DeleteObjects(miniogw.WithUplinkProject(ctx, project), bucket, objects, opts)

	for _, err := range errors {
		_ = l.log(ctx, err)
	}

	return deleted, errors
}

func (l *multiTenancyLayer) ListMultipartUploads(ctx context.Context, bucket, prefix, keyMarker, uploadIDMarker, delimiter string, maxUploads int) (result minio.ListMultipartsInfo, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.ListMultipartsInfo{}, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	result, err = l.layer.ListMultipartUploads(miniogw.WithUplinkProject(ctx, project), bucket, prefix, keyMarker, uploadIDMarker, delimiter, maxUploads)
	return result, l.log(ctx, err)
}

func (l *multiTenancyLayer) NewMultipartUpload(ctx context.Context, bucket, object string, opts minio.ObjectOptions) (uploadID string, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return "", err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	uploadID, err = l.layer.NewMultipartUpload(miniogw.WithUplinkProject(ctx, project), bucket, object, opts)
	return uploadID, l.log(ctx, err)
}

func (l *multiTenancyLayer) PutObjectPart(ctx context.Context, bucket, object, uploadID string, partID int, data *minio.PutObjReader, opts minio.ObjectOptions) (info minio.PartInfo, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.PartInfo{}, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	info, err = l.layer.PutObjectPart(miniogw.WithUplinkProject(ctx, project), bucket, object, uploadID, partID, data, opts)
	return info, l.log(ctx, err)
}

func (l *multiTenancyLayer) GetMultipartInfo(ctx context.Context, bucket string, object string, uploadID string, opts minio.ObjectOptions) (info minio.MultipartInfo, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.MultipartInfo{}, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	info, err = l.layer.GetMultipartInfo(miniogw.WithUplinkProject(ctx, project), bucket, object, uploadID, opts)
	return info, l.log(ctx, err)
}

func (l *multiTenancyLayer) ListObjectParts(ctx context.Context, bucket, object, uploadID string, partNumberMarker int, maxParts int, opts minio.ObjectOptions) (result minio.ListPartsInfo, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.ListPartsInfo{}, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	result, err = l.layer.ListObjectParts(miniogw.WithUplinkProject(ctx, project), bucket, object, uploadID, partNumberMarker, maxParts, opts)
	return result, l.log(ctx, err)
}

func (l *multiTenancyLayer) AbortMultipartUpload(ctx context.Context, bucket, object, uploadID string, opts minio.ObjectOptions) error {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	return l.log(ctx, l.layer.AbortMultipartUpload(miniogw.WithUplinkProject(ctx, project), bucket, object, uploadID, opts))
}

func (l *multiTenancyLayer) CompleteMultipartUpload(ctx context.Context, bucket, object, uploadID string, uploadedParts []minio.CompletePart, opts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.ObjectInfo{}, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	objInfo, err = l.layer.CompleteMultipartUpload(miniogw.WithUplinkProject(ctx, project), bucket, object, uploadID, uploadedParts, opts)
	return objInfo, l.log(ctx, err)
}

func (l *multiTenancyLayer) IsTaggingSupported() bool {
	return l.layer.IsTaggingSupported()
}

func (l *multiTenancyLayer) PutObjectTags(ctx context.Context, bucketName, objectPath string, tags string, opts minio.ObjectOptions) error {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	return l.log(ctx, l.layer.PutObjectTags(miniogw.WithUplinkProject(ctx, project), bucketName, objectPath, tags, opts))
}

func (l *multiTenancyLayer) GetObjectTags(ctx context.Context, bucketName, objectPath string, opts minio.ObjectOptions) (t *tags.Tags, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return nil, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	t, err = l.layer.GetObjectTags(miniogw.WithUplinkProject(ctx, project), bucketName, objectPath, opts)
	return t, l.log(ctx, err)
}

func (l *multiTenancyLayer) DeleteObjectTags(ctx context.Context, bucketName, objectPath string, opts minio.ObjectOptions) error {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	return l.log(ctx, l.layer.DeleteObjectTags(miniogw.WithUplinkProject(ctx, project), bucketName, objectPath, opts))
}

func getAccessGrant(ctx context.Context) string {
	credentials := middleware.GetAccess(ctx)
	if credentials == nil || credentials.AccessKey == "" {
		return ""
	}
	return credentials.AccessGrant
}

func (l *multiTenancyLayer) openProject(ctx context.Context, accessKey string) (_ *uplink.Project, err error) {
	defer mon.Task()(&ctx)(&err)

	// this happens when an anonymous request hits the gateway endpoint, e.g.
	// accessing http://localhost:7777 directly.
	if accessKey == "" {
		return nil, ErrAccessKeyEmpty
	}

	access, err := uplink.ParseAccess(accessKey)
	if err != nil {
		return nil, ErrAccessGrant.Wrap(err)
	}

	return l.setupProject(ctx, access)
}

func (l *multiTenancyLayer) setupProject(ctx context.Context, access *uplink.Access) (_ *uplink.Project, err error) {
	defer mon.Task()(&ctx)(&err)

	config := l.config
	config.UserAgent = getUserAgent(ctx)

	err = transport.SetConnectionPool(ctx, &config, l.connectionPool)
	if err != nil {
		return nil, err
	}

	return config.OpenProject(ctx, access)
}

func getUserAgent(ctx context.Context) string {
	userAgent := gatewayUserAgent
	reqInfo := logger.GetReqInfo(ctx)
	if reqInfo == nil {
		return userAgent
	}

	if reqInfo.UserAgent != "" {
		_, err := useragent.ParseEntries([]byte(reqInfo.UserAgent))
		if err != nil {
			return userAgent
		}
		userAgent = reqInfo.UserAgent + " " + userAgent
	}
	return userAgent
}
