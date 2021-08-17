// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"

	"github.com/minio/minio-go/v7/pkg/tags"
	minio "github.com/storj/minio/cmd"
	xhttp "github.com/storj/minio/cmd/http"
	"github.com/storj/minio/cmd/logger"
	"github.com/storj/minio/pkg/hash"
	"github.com/zeebo/errs"

	"storj.io/common/errs2"
	"storj.io/common/rpc/rpcpool"
	"storj.io/common/useragent"
	"storj.io/gateway-mt/pkg/server/gwlog"
	"storj.io/private/version"
	"storj.io/uplink"
	"storj.io/uplink/private/transport"
)

var (
	gatewayUserAgent = "Gateway-MT/" + version.Build.Version.String()

	// ErrAccessGrant occurs when failing to parse the access grant from the request.
	ErrAccessGrant = errs.Class("access grant")
)

// NewGateway implements returns a implementation of Gateway-MT compatible with Minio.
func NewGateway(config uplink.Config, connectionPool *rpcpool.Pool, compatibilityConfig S3CompatibilityConfig, insecureLogAll bool) (minio.ObjectLayer, error) {
	return &gateway{
		config:              config,
		connectionPool:      connectionPool,
		compatibilityConfig: compatibilityConfig,
		insecureLogAll:      insecureLogAll,
	}, nil
}

type gateway struct {
	minio.GatewayUnsupported
	config              uplink.Config
	connectionPool      *rpcpool.Pool
	compatibilityConfig S3CompatibilityConfig
	insecureLogAll      bool
}

func (gateway *gateway) IsTaggingSupported() bool {
	return true
}

func (gateway *gateway) DeleteBucket(ctx context.Context, bucketName string, forceDelete bool) (err error) {
	defer mon.Task()(&ctx)(&err)
	defer func() { gateway.log(ctx, err) }()

	project, err := gateway.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return convertError(err, bucketName, "")
	}
	defer func() {
		err = errs.Combine(err, project.Close())
	}()

	if forceDelete {
		_, err = project.DeleteBucketWithObjects(ctx, bucketName)
		return convertError(err, bucketName, "")
	}

	_, err = project.DeleteBucket(ctx, bucketName)
	return convertError(err, bucketName, "")
}

func (gateway *gateway) DeleteObject(ctx context.Context, bucketName, objectPath string, opts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	defer mon.Task()(&ctx)(&err)
	defer func() { gateway.log(ctx, err) }()

	project, err := gateway.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.ObjectInfo{}, err
	}
	defer func() {
		err = errs.Combine(err, project.Close())
	}()

	// TODO this should be removed and implemented on satellite side.
	// This call needs to occur prior to the DeleteObject call below, because
	// project.DeleteObject will return a nil error for a missing bucket. To
	// maintain consistency, we need to manually check if the bucket exists.
	_, err = project.StatBucket(ctx, bucketName)
	if err != nil {
		return minio.ObjectInfo{}, convertError(err, bucketName, objectPath)
	}

	object, err := project.DeleteObject(ctx, bucketName, objectPath)
	if err != nil {
		return minio.ObjectInfo{}, convertError(err, bucketName, objectPath)
	}

	return minioObjectInfo(bucketName, "", object), nil
}

func (gateway *gateway) DeleteObjects(ctx context.Context, bucketName string, objects []minio.ObjectToDelete, opts minio.ObjectOptions) (deleted []minio.DeletedObject, errs []error) {
	defer func() {
		for _, err := range errs {
			gateway.log(ctx, err)
		}
	}()
	// TODO: implement multiple object deletion in libuplink API
	errs = make([]error, len(objects))
	deleted = make([]minio.DeletedObject, len(objects))
	for i, object := range objects {
		_, deleteErr := gateway.DeleteObject(ctx, bucketName, object.ObjectName, opts)
		if deleteErr != nil && !errors.As(deleteErr, &minio.ObjectNotFound{}) {
			errs[i] = convertError(deleteErr, bucketName, object.ObjectName)
			continue
		}
		deleted[i].ObjectName = object.ObjectName
	}
	return deleted, errs
}

func (gateway *gateway) GetBucketInfo(ctx context.Context, bucketName string) (bucketInfo minio.BucketInfo, err error) {
	defer mon.Task()(&ctx)(&err)
	defer func() { gateway.log(ctx, err) }()

	project, err := gateway.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.BucketInfo{}, err
	}
	defer func() {
		err = errs.Combine(err, project.Close())
	}()

	bucket, err := project.StatBucket(ctx, bucketName)
	if err != nil {
		return minio.BucketInfo{}, convertError(err, bucketName, "")
	}

	return minio.BucketInfo{
		Name:    bucket.Name,
		Created: bucket.Created,
	}, nil
}

func (gateway *gateway) GetObjectNInfo(ctx context.Context, bucketName, objectPath string, rangeSpec *minio.HTTPRangeSpec, header http.Header, lockType minio.LockType, opts minio.ObjectOptions) (reader *minio.GetObjectReader, err error) {
	defer mon.Task()(&ctx)(&err)
	defer func() { gateway.log(ctx, err) }()

	project, err := gateway.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errs.Combine(err, project.Close())
	}()

	// TODO this should be removed and implemented on satellite side
	defer func() {
		err = checkBucketError(ctx, project, bucketName, objectPath, err)
	}()

	downloadOpts, err := rangeSpecToDownloadOptions(rangeSpec)
	if err != nil {
		return nil, err
	}

	download, err := project.DownloadObject(ctx, bucketName, objectPath, downloadOpts)
	if err != nil {
		return nil, convertError(err, bucketName, objectPath)
	}

	objectInfo := minioObjectInfo(bucketName, "", download.Info())
	downloadCloser := func() { _ = download.Close() }

	return minio.NewGetObjectReaderFromReader(download, objectInfo, opts, downloadCloser)
}

func rangeSpecToDownloadOptions(spec *minio.HTTPRangeSpec) (opts *uplink.DownloadOptions, err error) {
	switch {
	// Case 1: Not present -> represented by a nil RangeSpec
	case spec == nil:
		return nil, nil
	// Case 2: bytes=1-10 (absolute start and end offsets) -> RangeSpec{false, 1, 10}
	case spec.Start >= 0 && spec.End >= 0 && !spec.IsSuffixLength:
		return &uplink.DownloadOptions{
			Offset: spec.Start,
			Length: spec.End - spec.Start + 1,
		}, nil
	// Case 3: bytes=10- (absolute start offset with end offset unspecified) -> RangeSpec{false, 10, -1}
	case spec.Start >= 0 && spec.End == -1 && !spec.IsSuffixLength:
		return &uplink.DownloadOptions{
			Offset: spec.Start,
			Length: -1,
		}, nil
	// Case 4: bytes=-30 (suffix length specification) -> RangeSpec{true, -30, -1}
	case spec.Start <= 0 && spec.End == -1 && spec.IsSuffixLength:
		if spec.Start == 0 {
			return &uplink.DownloadOptions{Offset: 0, Length: 0}, nil
		}
		return &uplink.DownloadOptions{
			Offset: spec.Start,
			Length: -1,
		}, nil
	default:
		return nil, errs.New("Unexpected range specification case: %#v", spec)
	}
}

func (gateway *gateway) GetObject(ctx context.Context, bucketName, objectPath string, startOffset int64, length int64, writer io.Writer, etag string, opts minio.ObjectOptions) (err error) {
	defer mon.Task()(&ctx)(&err)
	defer func() { gateway.log(ctx, err) }()

	project, err := gateway.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return convertError(err, bucketName, objectPath)
	}
	defer func() {
		err = errs.Combine(err, project.Close())
	}()

	download, err := project.DownloadObject(ctx, bucketName, objectPath, &uplink.DownloadOptions{
		Offset: startOffset,
		Length: length,
	})
	if err != nil {
		// TODO this should be removed and implemented on satellite side
		err = checkBucketError(ctx, project, bucketName, objectPath, err)
		return convertError(err, bucketName, objectPath)
	}
	defer func() { err = errs.Combine(err, download.Close()) }()

	object := download.Info()
	if startOffset < 0 || length < -1 {
		return minio.InvalidRange{
			OffsetBegin:  startOffset,
			OffsetEnd:    startOffset + length,
			ResourceSize: object.System.ContentLength,
		}
	}

	_, err = io.Copy(writer, download)

	return convertError(err, bucketName, objectPath)
}

func (gateway *gateway) GetObjectInfo(ctx context.Context, bucketName, objectPath string, opts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	defer mon.Task()(&ctx)(&err)
	defer func() { gateway.log(ctx, err) }()

	project, err := gateway.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.ObjectInfo{}, err
	}
	defer func() {
		err = errs.Combine(err, project.Close())
	}()

	object, err := project.StatObject(ctx, bucketName, objectPath)
	if err != nil {
		// TODO this should be removed and implemented on satellite side
		err = checkBucketError(ctx, project, bucketName, objectPath, err)
		return minio.ObjectInfo{}, convertError(err, bucketName, objectPath)
	}

	return minioObjectInfo(bucketName, "", object), nil
}

func (gateway *gateway) PutObjectTags(ctx context.Context, bucketName, objectPath string, tags string, opts minio.ObjectOptions) (err error) {
	defer mon.Task()(&ctx)(&err)
	defer func() { gateway.log(ctx, err) }()

	project, err := gateway.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return err
	}
	defer func() {
		err = errs.Combine(err, project.Close())
	}()

	object, err := project.StatObject(ctx, bucketName, objectPath)
	if err != nil {
		// TODO this should be removed and implemented on satellite side
		err = checkBucketError(ctx, project, bucketName, objectPath, err)
		return convertError(err, bucketName, objectPath)
	}

	if _, ok := object.Custom["s3:tags"]; !ok && tags == "" {
		return nil
	}

	newMetadata := object.Custom.Clone()
	if tags == "" {
		delete(newMetadata, "s3:tags")
	} else {
		newMetadata["s3:tags"] = tags
	}

	err = project.UpdateObjectMetadata(ctx, bucketName, objectPath, newMetadata, nil)
	if err != nil {
		return convertError(err, bucketName, objectPath)
	}

	return nil
}

func (gateway *gateway) GetObjectTags(ctx context.Context, bucketName, objectPath string, opts minio.ObjectOptions) (t *tags.Tags, err error) {
	defer mon.Task()(&ctx)(&err)
	defer func() { gateway.log(ctx, err) }()

	project, err := gateway.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errs.Combine(err, project.Close())
	}()

	object, err := project.StatObject(ctx, bucketName, objectPath)
	if err != nil {
		// TODO this should be removed and implemented on satellite side
		err = checkBucketError(ctx, project, bucketName, objectPath, err)
		return nil, convertError(err, bucketName, objectPath)
	}

	t, err = tags.ParseObjectTags(object.Custom["s3:tags"])
	if err != nil {
		return nil, convertError(err, bucketName, objectPath)
	}

	return t, nil
}

func (gateway *gateway) DeleteObjectTags(ctx context.Context, bucketName, objectPath string, opts minio.ObjectOptions) (err error) {
	defer mon.Task()(&ctx)(&err)
	defer func() { gateway.log(ctx, err) }()

	project, err := gateway.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return err
	}
	defer func() {
		err = errs.Combine(err, project.Close())
	}()

	object, err := project.StatObject(ctx, bucketName, objectPath)
	if err != nil {
		// TODO this should be removed and implemented on satellite side
		err = checkBucketError(ctx, project, bucketName, objectPath, err)
		return convertError(err, bucketName, objectPath)
	}

	if _, ok := object.Custom["s3:tags"]; !ok {
		return nil
	}

	newMetadata := object.Custom.Clone()
	delete(newMetadata, "s3:tags")

	err = project.UpdateObjectMetadata(ctx, bucketName, objectPath, newMetadata, nil)
	if err != nil {
		return convertError(err, bucketName, objectPath)
	}

	return nil
}

func (gateway *gateway) ListBuckets(ctx context.Context) (items []minio.BucketInfo, err error) {
	defer mon.Task()(&ctx)(&err)
	defer func() { gateway.log(ctx, err) }()

	project, err := gateway.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errs.Combine(err, project.Close())
	}()

	buckets := project.ListBuckets(ctx, nil)
	for buckets.Next() {
		info := buckets.Item()
		items = append(items, minio.BucketInfo{
			Name:    info.Name,
			Created: info.Created,
		})
	}
	if buckets.Err() != nil {
		return nil, convertError(buckets.Err(), "", "")
	}
	return items, nil
}

// limitMaxKeys returns maxKeys limited to what gateway is configured to limit
// maxKeys to, aligned with paging limitations on the satellite side. It will
// also return the highest limit possible if maxKeys is not positive.
func (gateway *gateway) limitMaxKeys(maxKeys int) int {
	if maxKeys <= 0 || maxKeys >= gateway.compatibilityConfig.MaxKeysLimit {
		// Return max keys with a buffer to gather the continuation token to
		// avoid paging problems until we have a method in libuplink to get more
		// info about page boundaries.
		return gateway.compatibilityConfig.MaxKeysLimit - 1
	}
	return maxKeys
}

func (gateway *gateway) ListObjects(ctx context.Context, bucketName, prefix, marker, delimiter string, maxKeys int) (result minio.ListObjectsInfo, err error) {
	defer mon.Task()(&ctx)(&err)
	defer func() { gateway.log(ctx, err) }()

	if delimiter != "" && delimiter != "/" {
		return minio.ListObjectsInfo{}, minio.UnsupportedDelimiter{Delimiter: delimiter}
	}

	project, err := gateway.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return result, err
	}
	defer func() {
		err = errs.Combine(err, project.Close())
	}()

	// TODO this should be removed and implemented on satellite side
	defer func() {
		err = checkBucketError(ctx, project, bucketName, "", err)
	}()

	recursive := delimiter == ""

	startAfter := marker

	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		// N.B.: in this case, the most S3-compatible thing we could do
		// is ask the satellite to list all siblings of this prefix that
		// share the same parent encryption key, decrypt all of them,
		// then only return the ones that have this same unencrypted
		// prefix.
		// this is terrible from a performance perspective, and it turns
		// out, many of the usages of listing without a /-suffix are
		// simply to provide a sort of StatObject like feature. in fact,
		// for example, duplicity never calls list without a /-suffix
		// in a case where it expects to get back more than one result.
		// so, we could either
		// 1) return an error here, guaranteeing nothing works
		// 2) do the full S3 compatible thing, which has terrible
		//    performance for a really common case (StatObject-like
		//		functionality)
		// 3) handle strictly more of the use cases than #1 without
		//    loss of performance by turning this into a StatObject.
		// so we do #3 here. it's great!

		return listSingleObject(ctx, project, bucketName, prefix, startAfter, recursive, maxKeys)
	}

	list := project.ListObjects(ctx, bucketName, &uplink.ListObjectsOptions{
		Prefix:    prefix,
		Cursor:    strings.TrimPrefix(startAfter, prefix),
		Recursive: recursive,

		System: true,
		Custom: gateway.compatibilityConfig.IncludeCustomMetadataListing,
	})

	var objects []minio.ObjectInfo
	var prefixes []string

	limit := gateway.limitMaxKeys(maxKeys)
	for limit > 0 && list.Next() {
		object := list.Item()

		limit--

		if object.IsPrefix {
			prefixes = append(prefixes, object.Key)
		} else {
			objects = append(objects, minioObjectInfo(bucketName, "", object))
		}

		startAfter = object.Key
	}
	if list.Err() != nil {
		return result, convertError(list.Err(), bucketName, "")
	}

	more := list.Next()
	if list.Err() != nil {
		return result, convertError(list.Err(), bucketName, "")
	}

	result = minio.ListObjectsInfo{
		IsTruncated: more,
		Objects:     objects,
		Prefixes:    prefixes,
	}
	if more {
		result.NextMarker = startAfter
	}

	return result, nil
}

func listSingleObject(ctx context.Context, project *uplink.Project, bucketName, key, marker string, recursive bool, maxKeys int) (result minio.ListObjectsInfo, err error) {
	defer mon.Task()(&ctx)(&err)

	isTruncated, nextMarker, objects, prefixes, err := listSingle(ctx, project, bucketName, key, marker, recursive, maxKeys)

	return minio.ListObjectsInfo{
		IsTruncated: isTruncated,
		NextMarker:  nextMarker,
		Objects:     objects,
		Prefixes:    prefixes,
	}, err // already converted/wrapped
}

func (gateway *gateway) ListObjectsV2(ctx context.Context, bucketName, prefix, continuationToken, delimiter string, maxKeys int, fetchOwner bool, startAfter string) (result minio.ListObjectsV2Info, err error) {
	defer mon.Task()(&ctx)(&err)
	defer func() { gateway.log(ctx, err) }()

	if delimiter != "" && delimiter != "/" {
		return minio.ListObjectsV2Info{}, minio.UnsupportedDelimiter{Delimiter: delimiter}
	}

	project, err := gateway.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return result, err
	}
	defer func() {
		err = errs.Combine(err, project.Close())
	}()

	// TODO this should be removed and implemented on satellite side
	defer func() {
		err = checkBucketError(ctx, project, bucketName, "", err)
	}()

	recursive := delimiter == ""

	var startAfterPath string

	if startAfter != "" {
		startAfterPath = startAfter
	}
	if continuationToken != "" {
		startAfterPath = continuationToken
	}

	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		// N.B.: in this case, the most S3-compatible thing we could do
		// is ask the satellite to list all siblings of this prefix that
		// share the same parent encryption key, decrypt all of them,
		// then only return the ones that have this same unencrypted
		// prefix.
		// this is terrible from a performance perspective, and it turns
		// out, many of the usages of listing without a /-suffix are
		// simply to provide a sort of StatObject like feature. in fact,
		// for example, duplicity never calls list without a /-suffix
		// in a case where it expects to get back more than one result.
		// so, we could either
		// 1) return an error here, guaranteeing nothing works
		// 2) do the full S3 compatible thing, which has terrible
		//    performance for a really common case (StatObject-like
		//		functionality)
		// 3) handle strictly more of the use cases than #1 without
		//    loss of performance by turning this into a StatObject.
		// so we do #3 here. it's great!

		return listSingleObjectV2(ctx, project, bucketName, prefix, continuationToken, startAfterPath, recursive, maxKeys)
	}

	list := project.ListObjects(ctx, bucketName, &uplink.ListObjectsOptions{
		Prefix:    prefix,
		Cursor:    strings.TrimPrefix(startAfterPath, prefix),
		Recursive: recursive,

		System: true,
		Custom: gateway.compatibilityConfig.IncludeCustomMetadataListing,
	})

	var objects []minio.ObjectInfo
	var prefixes []string

	limit := gateway.limitMaxKeys(maxKeys)
	for limit > 0 && list.Next() {
		object := list.Item()

		limit--

		if object.IsPrefix {
			prefixes = append(prefixes, object.Key)
		} else {
			objects = append(objects, minioObjectInfo(bucketName, "", object))
		}

		startAfter = object.Key
	}
	if list.Err() != nil {
		return result, convertError(list.Err(), bucketName, "")
	}

	more := list.Next()
	if list.Err() != nil {
		return result, convertError(list.Err(), bucketName, "")
	}

	result = minio.ListObjectsV2Info{
		IsTruncated:       more,
		ContinuationToken: continuationToken,
		Objects:           objects,
		Prefixes:          prefixes,
	}
	if more {
		result.NextContinuationToken = startAfter
	}

	return result, nil
}

func listSingleObjectV2(ctx context.Context, project *uplink.Project, bucketName, key, continuationToken, startAfterPath string, recursive bool, maxKeys int) (result minio.ListObjectsV2Info, err error) {
	defer mon.Task()(&ctx)(&err)

	isTruncated, nextMarker, objects, prefixes, err := listSingle(ctx, project, bucketName, key, startAfterPath, recursive, maxKeys)

	return minio.ListObjectsV2Info{
		IsTruncated:           isTruncated,
		ContinuationToken:     continuationToken,
		NextContinuationToken: nextMarker,
		Objects:               objects,
		Prefixes:              prefixes,
	}, err // already converted/wrapped
}

func listSingle(ctx context.Context, project *uplink.Project, bucketName, key, marker string, recursive bool, maxKeys int) (isTruncated bool, nextMarker string, objects []minio.ObjectInfo, prefixes []string, err error) {
	defer mon.Task()(&ctx)(&err)

	if marker == "" {
		object, err := project.StatObject(ctx, bucketName, key)
		if err != nil {
			if !errors.Is(err, uplink.ErrObjectNotFound) {
				return false, "", nil, nil, convertError(err, bucketName, key)
			}
		} else {
			objects = append(objects, minioObjectInfo(bucketName, "", object))

			if maxKeys == 1 {
				return true, key, objects, nil, nil
			}
		}
	}

	if !recursive && (marker == "" || marker == key) {
		list := project.ListObjects(ctx, bucketName, &uplink.ListObjectsOptions{
			Prefix:    key + "/",
			Recursive: true,
			// Limit: 1, would be nice to set here
		})
		if list.Next() {
			prefixes = append(prefixes, key+"/")
		}
		if err := list.Err(); err != nil {
			return false, "", nil, nil, convertError(err, bucketName, key)
		}
	}

	return false, "", objects, prefixes, nil
}

func (gateway *gateway) MakeBucketWithLocation(ctx context.Context, bucketName string, opts minio.BucketOptions) (err error) {
	defer mon.Task()(&ctx)(&err)
	defer func() { gateway.log(ctx, err) }()

	project, err := gateway.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return convertError(err, bucketName, "")
	}
	defer func() {
		err = errs.Combine(err, project.Close())
	}()

	_, err = project.CreateBucket(ctx, bucketName)

	return convertError(err, bucketName, "")
}

func (gateway *gateway) CopyObject(ctx context.Context, srcBucket, srcObject, destBucket, destObject string, srcInfo minio.ObjectInfo, srcOpts, destOpts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	defer mon.Task()(&ctx)(&err)
	defer func() { gateway.log(ctx, err) }()

	if gateway.compatibilityConfig.DisableCopyObject {
		// Note: In production Gateway-MT, we want to return Not Implemented until we implement server-side copy
		return minio.ObjectInfo{}, minio.NotImplemented{API: "CopyObject"}
	}

	if srcObject == "" {
		return minio.ObjectInfo{}, minio.ObjectNameInvalid{Bucket: srcBucket}
	}
	if destObject == "" {
		return minio.ObjectInfo{}, minio.ObjectNameInvalid{Bucket: destBucket}
	}

	project, err := gateway.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.ObjectInfo{}, err
	}

	// TODO this should be removed and implemented on satellite side
	_, err = project.StatBucket(ctx, srcBucket)
	if err != nil {
		return minio.ObjectInfo{}, convertError(err, srcBucket, "")
	}

	// TODO this should be removed and implemented on satellite side
	if srcBucket != destBucket {
		_, err = project.StatBucket(ctx, destBucket)
		if err != nil {
			return minio.ObjectInfo{}, convertError(err, destBucket, "")
		}
	}

	if srcBucket == destBucket && srcObject == destObject {
		// Source and destination are the same. Do nothing, otherwise copying
		// the same object over itself may destroy it, especially if it is a
		// larger one.
		return srcInfo, nil
	}

	download, err := project.DownloadObject(ctx, srcBucket, srcObject, nil)
	if err != nil {
		return minio.ObjectInfo{}, convertError(err, srcBucket, srcObject)
	}
	defer func() {
		// TODO: this hides minio error
		err = errs.Combine(err, download.Close())
	}()

	upload, err := project.UploadObject(ctx, destBucket, destObject, nil)
	if err != nil {
		return minio.ObjectInfo{}, convertError(err, destBucket, destObject)
	}

	info := download.Info()
	err = upload.SetCustomMetadata(ctx, info.Custom)
	if err != nil {
		abortErr := upload.Abort()
		err = errs.Combine(err, abortErr)
		return minio.ObjectInfo{}, convertError(err, destBucket, destObject)
	}

	reader, err := hash.NewReader(download, info.System.ContentLength, "", "", info.System.ContentLength, true)
	if err != nil {
		abortErr := upload.Abort()
		err = errs.Combine(err, abortErr)
		return minio.ObjectInfo{}, convertError(err, destBucket, destObject)
	}

	_, err = io.Copy(upload, reader)
	if err != nil {
		abortErr := upload.Abort()
		err = errs.Combine(err, abortErr)
		return minio.ObjectInfo{}, convertError(err, destBucket, destObject)
	}

	err = upload.Commit()
	if err != nil {
		return minio.ObjectInfo{}, convertError(err, destBucket, destObject)
	}

	return minioObjectInfo(destBucket, hex.EncodeToString(reader.MD5Current()), upload.Info()), nil
}

func (gateway *gateway) PutObject(ctx context.Context, bucketName, objectPath string, data *minio.PutObjReader, opts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	defer mon.Task()(&ctx)(&err)
	defer func() { gateway.log(ctx, err) }()

	project, err := gateway.openProject(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.ObjectInfo{}, err
	}
	defer func() {
		err = errs.Combine(err, project.Close())
	}()

	// TODO this should be removed and implemented on satellite side
	defer func() {
		err = checkBucketError(ctx, project, bucketName, objectPath, err)
	}()

	if data == nil {
		hashReader, err := hash.NewReader(bytes.NewReader([]byte{}), 0, "", "", 0, true)
		if err != nil {
			return minio.ObjectInfo{}, convertError(err, bucketName, objectPath)
		}
		data = minio.NewPutObjReader(hashReader, nil, nil)
	}

	upload, err := project.UploadObject(ctx, bucketName, objectPath, nil)
	if err != nil {
		return minio.ObjectInfo{}, convertError(err, bucketName, objectPath)
	}

	_, err = io.Copy(upload, data)
	if err != nil {
		abortErr := upload.Abort()
		err = errs.Combine(err, abortErr)
		return minio.ObjectInfo{}, convertError(err, bucketName, objectPath)
	}

	if tagsStr, ok := opts.UserDefined[xhttp.AmzObjectTagging]; ok {
		opts.UserDefined["s3:tags"] = tagsStr
		delete(opts.UserDefined, xhttp.AmzObjectTagging)
	}

	opts.UserDefined["s3:etag"] = hex.EncodeToString(data.MD5Current())
	err = upload.SetCustomMetadata(ctx, opts.UserDefined)
	if err != nil {
		abortErr := upload.Abort()
		err = errs.Combine(err, abortErr)
		return minio.ObjectInfo{}, convertError(err, bucketName, objectPath)
	}

	err = upload.Commit()
	if err != nil {
		return minio.ObjectInfo{}, convertError(err, bucketName, objectPath)
	}

	return minioObjectInfo(bucketName, opts.UserDefined["s3:etag"], upload.Info()), nil
}

func (gateway *gateway) Shutdown(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)
	defer func() { gateway.log(ctx, err) }()

	return gateway.connectionPool.Close()
}

func (gateway *gateway) StorageInfo(ctx context.Context, local bool) (minio.StorageInfo, []error) {
	info := minio.StorageInfo{}
	info.Backend.Type = minio.BackendGateway
	info.Backend.GatewayOnline = true
	return info, nil
}

func (gateway *gateway) setupProject(ctx context.Context, access *uplink.Access) (_ *uplink.Project, err error) {
	defer mon.Task()(&ctx)(&err)

	config := gateway.config
	config.UserAgent = getUserAgent(ctx)

	err = transport.SetConnectionPool(ctx, &config, gateway.connectionPool)
	if err != nil {
		return nil, err
	}

	return config.OpenProject(ctx, access)
}

func (gateway *gateway) openProject(ctx context.Context, accessKey string) (_ *uplink.Project, err error) {
	defer mon.Task()(&ctx)(&err)

	// this happens when an anonymous request hits the gateway endpoint, e.g. accessing http://localhost:7777 directly.
	if accessKey == "" {
		return nil, convertError(ErrAccessGrant.New("access key is empty"), "", "")
	}

	access, err := uplink.ParseAccess(accessKey)
	if err != nil {
		return nil, convertError(ErrAccessGrant.Wrap(err), "", "")
	}

	return gateway.setupProject(ctx, access)
}

func (gateway *gateway) openProjectMultipart(ctx context.Context, accessKey string) (_ *uplink.Project, err error) {
	defer mon.Task()(&ctx)(&err)

	access, err := uplink.ParseAccess(accessKey)
	if err != nil {
		return nil, convertError(ErrAccessGrant.Wrap(err), "", "")
	}

	return gateway.setupProject(ctx, access)
}

// checkBucketError will stat the bucket if the provided error is not nil, in
// order to check if the proper error to return is really a bucket not found
// error. If the satellite has already returned this error, do not make an
// additional check.
func checkBucketError(ctx context.Context, project *uplink.Project, bucketName, object string, err error) error {
	if err != nil && !errors.Is(err, uplink.ErrBucketNotFound) {
		_, statErr := project.StatBucket(ctx, bucketName)
		if statErr != nil {
			return convertError(statErr, bucketName, object)
		}
	}
	return err
}

func convertError(err error, bucket, object string) error {
	switch {
	case err == nil:
		return nil
	case ErrAccessGrant.Has(err):
		// convert any errors parsing an access grant into InvalidArgument minio error type.
		// InvalidArgument seems to be the closest minio error to map access grant errors to, and
		// will respond with 400 Bad Request status.
		// we could create our own type from a minio.GenericError, but minio won't know what API
		// status code to map that to and default to a 500 (see api-errors.go toAPIErrorCode())
		// The other way would be to modify our minio fork directly, which is something already done
		// with the ProjectUsageLimit error type, but we're trying to avoid that as much as possible.
		return minio.InvalidArgument{Err: err}
	case errors.Is(err, uplink.ErrBucketNameInvalid):
		return minio.BucketNameInvalid{Bucket: bucket}
	case errors.Is(err, uplink.ErrBucketAlreadyExists):
		return minio.BucketAlreadyExists{Bucket: bucket}
	case errors.Is(err, uplink.ErrBucketNotFound):
		return minio.BucketNotFound{Bucket: bucket}
	case errors.Is(err, uplink.ErrBucketNotEmpty):
		return minio.BucketNotEmpty{Bucket: bucket}
	case errors.Is(err, uplink.ErrObjectKeyInvalid):
		return minio.ObjectNameInvalid{Bucket: bucket, Object: object}
	case errors.Is(err, uplink.ErrObjectNotFound):
		return minio.ObjectNotFound{Bucket: bucket, Object: object}
	case errors.Is(err, uplink.ErrBandwidthLimitExceeded):
		return minio.ProjectUsageLimit{}
	case errors.Is(err, uplink.ErrPermissionDenied):
		return minio.PrefixAccessDenied{Bucket: bucket, Object: object}
	case errors.Is(err, uplink.ErrTooManyRequests):
		return minio.SlowDown{}
	case errors.Is(err, io.ErrUnexpectedEOF):
		return minio.IncompleteBody{Bucket: bucket, Object: object}
	default:
		return err
	}
}

func minioObjectInfo(bucket, etag string, object *uplink.Object) minio.ObjectInfo {
	if object == nil {
		object = &uplink.Object{}
	}

	contentType := ""
	for k, v := range object.Custom {
		if strings.ToLower(k) == "content-type" {
			contentType = v
			break
		}
	}
	if etag == "" {
		etag = object.Custom["s3:etag"]
	}
	return minio.ObjectInfo{
		Bucket:      bucket,
		Name:        object.Key,
		Size:        object.System.ContentLength,
		ETag:        etag,
		ModTime:     object.System.Created,
		ContentType: contentType,
		UserDefined: object.Custom,
	}
}

func getAccessGrant(ctx context.Context) string {
	reqInfo := logger.GetReqInfo(ctx)
	if reqInfo == nil {
		return ""
	}
	return reqInfo.AccessGrant
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

// minioError checks if the given error is a minio error.
func minioError(err error) bool {
	// some minio errors are not minio.GenericError, so we need to check for these specifically.
	switch {
	case errors.As(err, &minio.ProjectUsageLimit{}), errors.As(err, &minio.SlowDown{}):
		return true
	default:
		return reflect.TypeOf(err).ConvertibleTo(reflect.TypeOf(minio.GenericError{}))
	}
}

// log all errors and relevant request information.
func (gateway *gateway) log(ctx context.Context, err error) {
	reqInfo := logger.GetReqInfo(ctx)
	if reqInfo == nil {
		return
	}

	// log any unexpected errors, or log every error if flag set
	if err != nil && (gateway.insecureLogAll || (!minioError(err) && !(errs2.IsCanceled(ctx.Err()) || errs2.IsCanceled(err)))) {
		reqInfo.SetTags("error", err.Error())
	}

	// logger.GetReqInfo(ctx) will get the ReqInfo from context minio created as a copy of the
	// parent request context. Our logging/metrics middleware can only see the parent context
	// without the ReqInfo value, so in order for it to get at the ReqInfo data, we copy it
	// to a separate log value both this gateway and our middleware can see, one that was
	// set in context from the middleware itself, and so is accessible here.
	// The alternative to this was to modify minio to avoid creating a ReqInfo and use the
	// same reference of a ReqInfo that was set in our middleware, but we want to avoid
	// modifying minio as much as we can help it.
	if log, ok := gwlog.FromContext(ctx); ok {
		copyReqInfo(log, reqInfo)
	}
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
	dst.AccessGrant = src.AccessGrant

	for _, tag := range src.GetTags() {
		dst.SetTags(tag.Key, tag.Val)
	}
}
