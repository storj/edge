// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package gw

import (
	"context"
	"net/http"
	"time"

	miniogo "github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/tags"
	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"

	"storj.io/common/identity"
	"storj.io/common/rpc/rpcpool"
	"storj.io/common/signing"
	"storj.io/common/storj"
	"storj.io/common/useragent"
	"storj.io/common/version"
	"storj.io/edge/pkg/server/gwlog"
	"storj.io/edge/pkg/server/middleware"
	"storj.io/gateway/miniogw"
	minio "storj.io/minio/cmd"
	"storj.io/minio/cmd/logger"
	"storj.io/minio/pkg/auth"
	objectlock "storj.io/minio/pkg/bucket/object/lock"
	"storj.io/minio/pkg/bucket/versioning"
	"storj.io/uplink"
	"storj.io/uplink/private/bucket"
	"storj.io/uplink/private/project"
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
		Code:       "AccessKeyEmpty",
		StatusCode: http.StatusUnauthorized,
		Message:    "Access key is empty.",
	}
)

// NewMultiTenantLayer initializes and returns new MultiTenancyLayer. A properly
// closed object layer will also close connectionPool.
func NewMultiTenantLayer(gateway minio.Gateway, satelliteConnectionPool *rpcpool.Pool, connectionPool *rpcpool.Pool, config uplink.Config, satelliteIdentities []*identity.FullIdentity) (*MultiTenancyLayer, error) {
	layer, err := gateway.NewGatewayLayer(auth.Credentials{})

	signers := make(map[storj.NodeID]signing.Signer, len(satelliteIdentities))
	for _, ident := range satelliteIdentities {
		signers[ident.ID] = signing.SignerFromFullIdentity(ident)
	}

	return &MultiTenancyLayer{
		layer:                   layer,
		satelliteConnectionPool: satelliteConnectionPool,
		connectionPool:          connectionPool,
		satelliteSigners:        signers,
		config:                  config,
	}, err
}

// MultiTenancyLayer implements multi-tenant minio.ObjectLayer that logs
// responses.
type MultiTenancyLayer struct {
	minio.GatewayUnsupported

	layer                   minio.ObjectLayer
	satelliteConnectionPool *rpcpool.Pool
	connectionPool          *rpcpool.Pool
	satelliteSigners        map[storj.NodeID]signing.Signer

	config uplink.Config
}

// log all errors and relevant request information.
func (l *MultiTenancyLayer) log(ctx context.Context, err error) error {
	reqInfo := logger.GetReqInfo(ctx)
	if reqInfo == nil {
		mon.Event("multi_tenant_layer_error_not_logged")
		return err
	}

	if err != nil {
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

// Shutdown is a multi-tenant wrapping of storj.io/gateway.(*gatewayLayer).Shutdown.
func (l *MultiTenancyLayer) Shutdown(ctx context.Context) error {
	return l.log(ctx, errs.Combine(l.connectionPool.Close(), l.satelliteConnectionPool.Close()))
}

// StorageInfo is a multi-tenant wrapping of storj.io/gateway.(*gatewayLayer).StorageInfo.
func (l *MultiTenancyLayer) StorageInfo(ctx context.Context) (minio.StorageInfo, []error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.StorageInfo{}, []error{err}
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	info, errors := l.layer.StorageInfo(miniogw.WithUplinkProject(ctx, project))

	for _, err := range errors {
		_ = l.log(ctx, err)
	}

	return info, errors
}

// MakeBucketWithLocation is a multi-tenant wrapping of storj.io/gateway.(*gatewayLayer).MakeBucketWithLocation.
func (l *MultiTenancyLayer) MakeBucketWithLocation(ctx context.Context, bucket string, opts minio.BucketOptions) error {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	return l.log(ctx, l.layer.MakeBucketWithLocation(miniogw.WithUplinkProject(ctx, project), bucket, opts))
}

// GetBucketInfo is a multi-tenant wrapping of storj.io/gateway.(*gatewayLayer).GetBucketInfo.
func (l *MultiTenancyLayer) GetBucketInfo(ctx context.Context, bucket string) (bucketInfo minio.BucketInfo, err error) {
	accessGrant := getAccessGrant(ctx)

	// Some S3 (like AWS S3) implementations allow anonymous checks for bucket
	// existence, but we explicitly forbid those and return
	// `minio.NotImplemented`, which seems to be the most appropriate response
	// in this case.
	if accessGrant == "" {
		return minio.BucketInfo{}, minio.NotImplemented{Message: "GetBucketInfo (anonymous)"}
	}

	project, err := l.openProject(ctx, accessGrant)
	if err != nil {
		return minio.BucketInfo{}, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	bucketInfo, err = l.layer.GetBucketInfo(miniogw.WithUplinkProject(ctx, project), bucket)
	return bucketInfo, l.log(ctx, err)
}

// GetBucketLocation is meant to be used for S3's
// https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLocation.html
// and responds with the location that the bucket's placement is annotated with
// (if any) on the satellite and any error encountered.
func (l *MultiTenancyLayer) GetBucketLocation(ctx context.Context, bucketName string) (location string, err error) {
	if err = miniogw.ValidateBucket(ctx, bucketName); err != nil {
		return "", l.log(ctx, minio.BucketNameInvalid{Bucket: bucketName})
	}

	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return "", err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	location, err = bucket.GetBucketLocation(ctx, project, bucketName)
	return location, l.log(ctx, miniogw.ConvertError(err, bucketName, ""))
}

// GetBucketVersioning retrieves versioning configuration of a bucket.
func (l *MultiTenancyLayer) GetBucketVersioning(ctx context.Context, bucket string) (versioning *versioning.Versioning, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return nil, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	versioning, err = l.layer.GetBucketVersioning(miniogw.WithUplinkProject(ctx, project), bucket)
	return versioning, l.log(ctx, err)
}

// SetBucketVersioning enables versioning on a bucket.
func (l *MultiTenancyLayer) SetBucketVersioning(ctx context.Context, bucket string, v *versioning.Versioning) error {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	err = l.layer.SetBucketVersioning(miniogw.WithUplinkProject(ctx, project), bucket, v)
	return l.log(ctx, err)
}

// ListBuckets is a multi-tenant wrapping of storj.io/gateway.(*gatewayLayer).ListBuckets.
func (l *MultiTenancyLayer) ListBuckets(ctx context.Context) (buckets []minio.BucketInfo, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return nil, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	buckets, err = l.layer.ListBuckets(miniogw.WithUplinkProject(ctx, project))
	return buckets, l.log(ctx, err)
}

// BucketWithAttributionInfo represents a bucket with attribution metadata.
type BucketWithAttributionInfo struct {
	Name        string
	Created     time.Time
	Attribution string
}

// ListBucketsWithAttribution is like ListBuckets, but it associates information
// about attribution (if any) with each bucket.
func (l *MultiTenancyLayer) ListBucketsWithAttribution(ctx context.Context) (buckets []BucketWithAttributionInfo, err error) {
	defer mon.Task()(&ctx)(&err)

	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return nil, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	it := bucket.ListBucketsWithAttribution(ctx, project, nil)

	for it.Next() {
		buckets = append(buckets, BucketWithAttributionInfo{
			Name:        it.Item().Name,
			Created:     it.Item().Created,
			Attribution: it.Item().Attribution,
		})
	}

	return buckets, l.log(ctx, miniogw.ConvertError(it.Err(), "", ""))
}

// DeleteBucket is a multi-tenant wrapping of storj.io/gateway.(*gatewayLayer).DeleteBucket.
func (l *MultiTenancyLayer) DeleteBucket(ctx context.Context, bucket string, forceDelete bool) error {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	return l.log(ctx, l.layer.DeleteBucket(miniogw.WithUplinkProject(ctx, project), bucket, forceDelete))
}

// GetObjectLockConfig is a multi-tenant wrapping of storj.io/gateway.(*gatewayLayer).GetObjectLockConfig.
func (l *MultiTenancyLayer) GetObjectLockConfig(ctx context.Context, bucket string) (objectLockConfig *objectlock.Config, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return &objectlock.Config{}, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	objectLockConfig, err = l.layer.GetObjectLockConfig(miniogw.WithUplinkProject(ctx, project), bucket)
	return objectLockConfig, l.log(ctx, err)
}

// SetObjectLockConfig is a multi-tenant wrapping of storj.io/gateway.(*gatewayLayer).SetObjectLockConfig.
func (l *MultiTenancyLayer) SetObjectLockConfig(ctx context.Context, bucket string, config *objectlock.Config) (err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	return l.log(ctx, l.layer.SetObjectLockConfig(miniogw.WithUplinkProject(ctx, project), bucket, config))
}

// GetObjectLegalHold is a multi-tenant wrapping of storj.io/gateway.(*gatewayLayer).GetObjectLegalHold.
func (l *MultiTenancyLayer) GetObjectLegalHold(ctx context.Context, bucket, object, version string) (_ *objectlock.ObjectLegalHold, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return nil, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	lh, err := l.layer.GetObjectLegalHold(miniogw.WithUplinkProject(ctx, project), bucket, object, version)

	return lh, l.log(ctx, err)
}

// SetObjectLegalHold is a multi-tenant wrapping of storj.io/gateway.(*gatewayLayer).SetObjectLegalHold.
func (l *MultiTenancyLayer) SetObjectLegalHold(ctx context.Context, bucket, object, version string, lh *objectlock.ObjectLegalHold) (err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	return l.log(ctx, l.layer.SetObjectLegalHold(miniogw.WithUplinkProject(ctx, project), bucket, object, version, lh))
}

// GetObjectRetention is a multi-tenant wrapping of storj.io/gateway.(*gatewayLayer).GetObjectRetention.
func (l *MultiTenancyLayer) GetObjectRetention(ctx context.Context, bucket, object, version string) (_ *objectlock.ObjectRetention, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return nil, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	retention, err := l.layer.GetObjectRetention(miniogw.WithUplinkProject(ctx, project), bucket, object, version)

	return retention, l.log(ctx, err)
}

// SetObjectRetention is a multi-tenant wrapping of storj.io/gateway.(*gatewayLayer).SetObjectRetention.
func (l *MultiTenancyLayer) SetObjectRetention(ctx context.Context, bucket, object, version string, r minio.ObjectOptions) (err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	return l.log(ctx, l.layer.SetObjectRetention(miniogw.WithUplinkProject(ctx, project), bucket, object, version, r))
}

// ListObjects is a multi-tenant wrapping of storj.io/gateway.(*gatewayLayer).ListObjects.
func (l *MultiTenancyLayer) ListObjects(ctx context.Context, bucket, prefix, marker, delimiter string, maxKeys int) (result minio.ListObjectsInfo, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.ListObjectsInfo{}, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	result, err = l.layer.ListObjects(miniogw.WithUplinkProject(ctx, project), bucket, prefix, marker, delimiter, maxKeys)
	return result, l.log(ctx, err)
}

// ListObjectsV2 is a multi-tenant wrapping of storj.io/gateway.(*gatewayLayer).ListObjectsV2.
func (l *MultiTenancyLayer) ListObjectsV2(ctx context.Context, bucket, prefix, continuationToken, delimiter string, maxKeys int, fetchOwner bool, startAfter string) (result minio.ListObjectsV2Info, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.ListObjectsV2Info{}, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	result, err = l.layer.ListObjectsV2(miniogw.WithUplinkProject(ctx, project), bucket, prefix, continuationToken, delimiter, maxKeys, fetchOwner, startAfter)
	return result, l.log(ctx, err)
}

// ListObjectVersions returns information about all versions of the objects in a bucket.
func (l *MultiTenancyLayer) ListObjectVersions(ctx context.Context, bucket, prefix, marker, versionMarker, delimiter string, maxKeys int) (result minio.ListObjectVersionsInfo, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.ListObjectVersionsInfo{}, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	result, err = l.layer.ListObjectVersions(miniogw.WithUplinkProject(ctx, project), bucket, prefix, marker, versionMarker, delimiter, maxKeys)
	return result, l.log(ctx, err)
}

// GetObjectNInfo is a multi-tenant wrapping of storj.io/gateway.(*gatewayLayer).GetObjectNInfo.
func (l *MultiTenancyLayer) GetObjectNInfo(ctx context.Context, bucket, object string, rs *minio.HTTPRangeSpec, h http.Header, lockType minio.LockType, opts minio.ObjectOptions) (reader *minio.GetObjectReader, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return nil, err
	}

	reader, err = l.layer.GetObjectNInfo(miniogw.WithUplinkProject(ctx, project), bucket, object, rs, h, lockType, opts)
	if err != nil {
		err = errs.Combine(err, project.Close())
	} else {
		reader.AppendCleanupFunc(func() { _ = project.Close() })
	}

	return reader, l.log(ctx, err)
}

// GetObjectInfo is a multi-tenant wrapping of storj.io/gateway.(*gatewayLayer).GetObjectInfo.
func (l *MultiTenancyLayer) GetObjectInfo(ctx context.Context, bucket, object string, opts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.ObjectInfo{}, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	objInfo, err = l.layer.GetObjectInfo(miniogw.WithUplinkProject(ctx, project), bucket, object, opts)
	return objInfo, l.log(ctx, err)
}

// PutObject is a multi-tenant wrapping of storj.io/gateway.(*gatewayLayer).PutObject.
func (l *MultiTenancyLayer) PutObject(ctx context.Context, bucket, object string, data *minio.PutObjReader, opts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.ObjectInfo{}, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	objInfo, err = l.layer.PutObject(miniogw.WithUplinkProject(ctx, project), bucket, object, data, opts)

	return objInfo, l.log(ctx, err)
}

// CopyObject is a multi-tenant wrapping of storj.io/gateway.(*gatewayLayer).CopyObject.
func (l *MultiTenancyLayer) CopyObject(ctx context.Context, srcBucket, srcObject, destBucket, destObject string, srcInfo minio.ObjectInfo, srcOpts, destOpts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.ObjectInfo{}, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	objInfo, err = l.layer.CopyObject(miniogw.WithUplinkProject(ctx, project), srcBucket, srcObject, destBucket, destObject, srcInfo, srcOpts, destOpts)
	return objInfo, l.log(ctx, err)
}

// DeleteObject is a multi-tenant wrapping of storj.io/gateway.(*gatewayLayer).DeleteObject.
func (l *MultiTenancyLayer) DeleteObject(ctx context.Context, bucket, object string, opts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.ObjectInfo{}, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	objInfo, err = l.layer.DeleteObject(miniogw.WithUplinkProject(ctx, project), bucket, object, opts)
	return objInfo, l.log(ctx, err)
}

// DeleteObjects is a multi-tenant wrapping of storj.io/gateway.(*gatewayLayer).DeleteObjects.
func (l *MultiTenancyLayer) DeleteObjects(ctx context.Context, bucket string, objects []minio.ObjectToDelete, opts minio.ObjectOptions) (deleted []minio.DeletedObject, deleteErrors []minio.DeleteObjectsError, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return nil, nil, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	deleted, deleteErrors, err = l.layer.DeleteObjects(miniogw.WithUplinkProject(ctx, project), bucket, objects, opts)
	return deleted, deleteErrors, l.log(ctx, err)
}

// ListMultipartUploads is a multi-tenant wrapping of storj.io/gateway.(*gatewayLayer).ListMultipartUploads.
func (l *MultiTenancyLayer) ListMultipartUploads(ctx context.Context, bucket, prefix, keyMarker, uploadIDMarker, delimiter string, maxUploads int) (result minio.ListMultipartsInfo, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.ListMultipartsInfo{}, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	result, err = l.layer.ListMultipartUploads(miniogw.WithUplinkProject(ctx, project), bucket, prefix, keyMarker, uploadIDMarker, delimiter, maxUploads)
	return result, l.log(ctx, err)
}

// NewMultipartUpload is a multi-tenant wrapping of storj.io/gateway.(*gatewayLayer).NewMultipartUpload.
func (l *MultiTenancyLayer) NewMultipartUpload(ctx context.Context, bucket, object string, opts minio.ObjectOptions) (uploadID string, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return "", err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	uploadID, err = l.layer.NewMultipartUpload(miniogw.WithUplinkProject(ctx, project), bucket, object, opts)
	return uploadID, l.log(ctx, err)
}

// PutObjectPart is a multi-tenant wrapping of storj.io/gateway.(*gatewayLayer).PutObjectPart.
func (l *MultiTenancyLayer) PutObjectPart(ctx context.Context, bucket, object, uploadID string, partID int, data *minio.PutObjReader, opts minio.ObjectOptions) (info minio.PartInfo, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.PartInfo{}, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	info, err = l.layer.PutObjectPart(miniogw.WithUplinkProject(ctx, project), bucket, object, uploadID, partID, data, opts)
	return info, l.log(ctx, err)
}

// GetMultipartInfo is a multi-tenant wrapping of storj.io/gateway.(*gatewayLayer).GetMultipartInfo.
func (l *MultiTenancyLayer) GetMultipartInfo(ctx context.Context, bucket string, object string, uploadID string, opts minio.ObjectOptions) (info minio.MultipartInfo, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.MultipartInfo{}, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	info, err = l.layer.GetMultipartInfo(miniogw.WithUplinkProject(ctx, project), bucket, object, uploadID, opts)
	return info, l.log(ctx, err)
}

// ListObjectParts is a multi-tenant wrapping of storj.io/gateway.(*gatewayLayer).ListObjectParts.
func (l *MultiTenancyLayer) ListObjectParts(ctx context.Context, bucket, object, uploadID string, partNumberMarker int, maxParts int, opts minio.ObjectOptions) (result minio.ListPartsInfo, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.ListPartsInfo{}, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	result, err = l.layer.ListObjectParts(miniogw.WithUplinkProject(ctx, project), bucket, object, uploadID, partNumberMarker, maxParts, opts)
	return result, l.log(ctx, err)
}

// AbortMultipartUpload is a multi-tenant wrapping of storj.io/gateway.(*gatewayLayer).AbortMultipartUpload.
func (l *MultiTenancyLayer) AbortMultipartUpload(ctx context.Context, bucket, object, uploadID string, opts minio.ObjectOptions) error {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	return l.log(ctx, l.layer.AbortMultipartUpload(miniogw.WithUplinkProject(ctx, project), bucket, object, uploadID, opts))
}

// CompleteMultipartUpload is a multi-tenant wrapping of storj.io/gateway.(*gatewayLayer).CompleteMultipartUpload.
func (l *MultiTenancyLayer) CompleteMultipartUpload(ctx context.Context, bucket, object, uploadID string, uploadedParts []minio.CompletePart, opts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.ObjectInfo{}, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	objInfo, err = l.layer.CompleteMultipartUpload(miniogw.WithUplinkProject(ctx, project), bucket, object, uploadID, uploadedParts, opts)
	return objInfo, l.log(ctx, err)
}

// IsTaggingSupported is a multi-tenant wrapping of storj.io/gateway.(*gatewayLayer).IsTaggingSupported.
func (l *MultiTenancyLayer) IsTaggingSupported() bool {
	return l.layer.IsTaggingSupported()
}

// PutObjectTags is a multi-tenant wrapping of storj.io/gateway.(*gatewayLayer).PutObjectTags.
func (l *MultiTenancyLayer) PutObjectTags(ctx context.Context, bucketName, objectPath string, tags string, opts minio.ObjectOptions) (minio.ObjectInfo, error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.ObjectInfo{}, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	objInfo, err := l.layer.PutObjectTags(miniogw.WithUplinkProject(ctx, project), bucketName, objectPath, tags, opts)

	return objInfo, l.log(ctx, err)
}

// GetObjectTags is a multi-tenant wrapping of storj.io/gateway.(*gatewayLayer).GetObjectTags.
func (l *MultiTenancyLayer) GetObjectTags(ctx context.Context, bucketName, objectPath string, opts minio.ObjectOptions) (t *tags.Tags, err error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return nil, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	t, err = l.layer.GetObjectTags(miniogw.WithUplinkProject(ctx, project), bucketName, objectPath, opts)
	return t, l.log(ctx, err)
}

// DeleteObjectTags is a multi-tenant wrapping of storj.io/gateway.(*gatewayLayer).DeleteObjectTags.
func (l *MultiTenancyLayer) DeleteObjectTags(ctx context.Context, bucketName, objectPath string, opts minio.ObjectOptions) (minio.ObjectInfo, error) {
	project, err := l.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.ObjectInfo{}, err
	}

	defer func() { err = errs.Combine(err, project.Close()) }()

	objInfo, err := l.layer.DeleteObjectTags(miniogw.WithUplinkProject(ctx, project), bucketName, objectPath, opts)

	return objInfo, l.log(ctx, err)
}

func getAccessGrant(ctx context.Context) string {
	credentials := middleware.GetAccess(ctx)
	if credentials == nil || credentials.AccessKey == "" {
		return ""
	}
	return credentials.AccessGrant
}

func (l *MultiTenancyLayer) openProject(ctx context.Context, accessKey string) (_ *uplink.Project, err error) {
	defer mon.Task()(&ctx)(&err)

	// this happens when an anonymous request hits the gateway endpoint, e.g.
	// accessing http://localhost:20010 directly.
	if accessKey == "" {
		return nil, ErrAccessKeyEmpty
	}

	access, err := uplink.ParseAccess(accessKey)
	if err != nil {
		return nil, ErrAccessGrant.Wrap(err)
	}

	return l.setupProject(ctx, access)
}

func (l *MultiTenancyLayer) setupProject(ctx context.Context, access *uplink.Access) (_ *uplink.Project, err error) {
	defer mon.Task()(&ctx)(&err)

	config := l.config
	config.UserAgent = getUserAgent(ctx)

	err = transport.SetConnectionPool(ctx, &config, l.connectionPool)
	if err != nil {
		return nil, err
	}

	err = transport.SetSatelliteConnectionPool(ctx, &config, l.satelliteConnectionPool)
	if err != nil {
		return nil, err
	}

	proj, err := config.OpenProject(ctx, access)
	if err != nil {
		return nil, err
	}

	if url, err := storj.ParseNodeURL(access.SatelliteAddress()); err == nil && !url.ID.IsZero() {
		if signer, exists := l.satelliteSigners[url.ID]; exists {
			project.SetSatelliteSigner(proj, signer)
		}
	}

	return proj, nil
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
