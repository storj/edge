// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"context"
	"crypto/md5" /* #nosec G501 */ // Is only used for calculating a hash of the ETags of the all the parts of a multipart upload.
	"encoding/hex"
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"

	minio "github.com/storj/minio/cmd"
	xhttp "github.com/storj/minio/cmd/http"
	"github.com/zeebo/errs"

	"storj.io/common/sync2"
	"storj.io/uplink"
)

func (gateway *gateway) NewMultipartUpload(ctx context.Context, bucket, object string, opts minio.ObjectOptions) (uploadID string, err error) {
	defer mon.Task()(&ctx)(&err)
	defer func() { gateway.log(ctx, err) }()

	project, err := gateway.openProjectMultipart(ctx, getAccessGrant(ctx))
	if err != nil {
		return "", err
	}
	defer func() {
		err = errs.Combine(err, project.Close())
	}()

	info, err := project.BeginUpload(ctx, bucket, object, nil)
	if err != nil {
		return "", convertMultipartError(err, bucket, object, "")
	}
	return info.UploadID, nil
}

func (gateway *gateway) GetMultipartInfo(ctx context.Context, bucket string, object string, uploadID string, opts minio.ObjectOptions) (info minio.MultipartInfo, err error) {
	defer mon.Task()(&ctx)(&err)
	defer func() { gateway.log(ctx, err) }()

	if bucket == "" {
		return minio.MultipartInfo{}, minio.BucketNameInvalid{}
	}

	if object == "" {
		return minio.MultipartInfo{}, minio.ObjectNameInvalid{}
	}

	if uploadID == "" {
		return minio.MultipartInfo{}, minio.InvalidUploadID{}
	}

	project, err := gateway.openProjectMultipart(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.MultipartInfo{}, err
	}
	defer func() {
		err = errs.Combine(err, project.Close())
	}()

	info.Bucket = bucket
	info.Object = object
	info.UploadID = uploadID

	list := project.ListUploads(ctx, bucket, &uplink.ListUploadsOptions{
		Prefix: object,
		System: true,
		Custom: gateway.compatibilityConfig.IncludeCustomMetadataListing,
	})

	for list.Next() {
		obj := list.Item()
		if obj.UploadID == uploadID {
			return minioMultipartInfo(bucket, obj), nil
		}
	}
	if list.Err() != nil {
		return minio.MultipartInfo{}, convertError(list.Err(), bucket, object)
	}
	return minio.MultipartInfo{}, minio.ObjectNotFound{Bucket: bucket, Object: object}
}

func (gateway *gateway) PutObjectPart(ctx context.Context, bucket, object, uploadID string, partID int, data *minio.PutObjReader, opts minio.ObjectOptions) (info minio.PartInfo, err error) {
	defer mon.Task()(&ctx)(&err)
	defer func() { gateway.log(ctx, err) }()

	if partID < 1 || int64(partID) > math.MaxUint32 {
		return minio.PartInfo{}, minio.InvalidArgument{
			Bucket: bucket,
			Object: object,
			Err:    errs.New("partID is out of range."),
		}
	}

	project, err := gateway.openProjectMultipart(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.PartInfo{}, err
	}
	defer func() {
		err = errs.Combine(err, project.Close())
	}()

	partUpload, err := project.UploadPart(ctx, bucket, object, uploadID, uint32(partID-1))
	if err != nil {
		return minio.PartInfo{}, convertMultipartError(err, bucket, object, uploadID)
	}

	_, err = sync2.Copy(ctx, partUpload, data)
	if err != nil {
		abortErr := partUpload.Abort()
		err = errs.Combine(err, abortErr)
		return minio.PartInfo{}, convertMultipartError(err, bucket, object, uploadID)
	}

	err = partUpload.SetETag([]byte(data.MD5CurrentHexString())) // TODO is MD5CurrentHexString correct?
	if err != nil {
		abortErr := partUpload.Abort()
		err = errs.Combine(err, abortErr)
		return minio.PartInfo{}, convertMultipartError(err, bucket, object, uploadID)
	}

	err = partUpload.Commit()
	if err != nil {
		return minio.PartInfo{}, convertMultipartError(err, bucket, object, uploadID)
	}

	part := partUpload.Info()
	return minio.PartInfo{
		PartNumber:   int(part.PartNumber + 1),
		Size:         part.Size,
		ActualSize:   part.Size,
		ETag:         string(part.ETag),
		LastModified: part.Modified,
	}, nil
}

func (gateway *gateway) AbortMultipartUpload(ctx context.Context, bucket, object, uploadID string, _ minio.ObjectOptions) (err error) {
	defer mon.Task()(&ctx)(&err)
	defer func() { gateway.log(ctx, err) }()

	project, err := gateway.openProjectMultipart(ctx, getAccessGrant(ctx))
	if err != nil {
		return err
	}
	defer func() {
		err = errs.Combine(err, project.Close())
	}()

	err = project.AbortUpload(ctx, bucket, object, uploadID)
	if err != nil {
		// it's not clear AbortMultipartUpload should return a 404 for objects not found
		// minio tests only cover bucket not found and invalid id
		if errors.Is(err, uplink.ErrObjectNotFound) {
			return nil
		}
		return convertMultipartError(err, bucket, object, uploadID)
	}
	return nil
}

func (gateway *gateway) CompleteMultipartUpload(ctx context.Context, bucket, object, uploadID string, uploadedParts []minio.CompletePart, opts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	defer mon.Task()(&ctx)(&err)
	defer func() { gateway.log(ctx, err) }()

	project, err := gateway.openProjectMultipart(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.ObjectInfo{}, err
	}
	defer func() {
		err = errs.Combine(err, project.Close())
	}()

	// TODO: Check that ETag of uploadedParts match the ETags stored in metabase.
	etag, err := multipartUploadETag(uploadedParts)
	if err != nil {
		return minio.ObjectInfo{}, convertMultipartError(err, bucket, object, uploadID)
	}

	if tagsStr, ok := opts.UserDefined[xhttp.AmzObjectTagging]; ok {
		opts.UserDefined["s3:tags"] = tagsStr
		delete(opts.UserDefined, xhttp.AmzObjectTagging)
	}

	metadata := uplink.CustomMetadata(opts.UserDefined).Clone()
	metadata["s3:etag"] = etag

	obj, err := project.CommitUpload(ctx, bucket, object, uploadID, &uplink.CommitUploadOptions{
		CustomMetadata: metadata,
	})
	if err != nil {
		return minio.ObjectInfo{}, convertMultipartError(err, bucket, object, uploadID)
	}

	return minioObjectInfo(bucket, etag, obj), nil
}

func (gateway *gateway) ListObjectParts(ctx context.Context, bucket, object, uploadID string, partNumberMarker int, maxParts int, opts minio.ObjectOptions) (result minio.ListPartsInfo, err error) {
	defer mon.Task()(&ctx)(&err)
	defer func() { gateway.log(ctx, err) }()

	project, err := gateway.openProjectMultipart(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.ListPartsInfo{}, err
	}
	defer func() {
		err = errs.Combine(err, project.Close())
	}()

	list := project.ListUploadParts(ctx, bucket, object, uploadID, &uplink.ListUploadPartsOptions{
		Cursor: uint32(partNumberMarker - 1),
	})

	parts := make([]minio.PartInfo, 0, maxParts)

	limit := maxParts
	for (limit > 0 || maxParts == 0) && list.Next() {
		limit--
		part := list.Item()
		parts = append(parts, minio.PartInfo{
			PartNumber:   int(part.PartNumber + 1),
			LastModified: part.Modified,
			ETag:         string(part.ETag), // Entity tag returned when the part was initially uploaded.
			Size:         part.Size,         // Size in bytes of the part.
			ActualSize:   part.Size,         // Decompressed Size.
		})
	}
	if list.Err() != nil {
		return result, convertMultipartError(list.Err(), bucket, object, uploadID)
	}

	more := list.Next()
	if list.Err() != nil {
		return result, convertMultipartError(list.Err(), bucket, object, uploadID)
	}

	sort.Slice(parts, func(i, k int) bool {
		return parts[i].PartNumber < parts[k].PartNumber
	})
	return minio.ListPartsInfo{
		Bucket:               bucket,
		Object:               object,
		UploadID:             uploadID,
		StorageClass:         "",               // TODO
		PartNumberMarker:     partNumberMarker, // Part number after which listing begins.
		NextPartNumberMarker: partNumberMarker, // TODO Next part number marker to be used if list is truncated
		MaxParts:             maxParts,
		IsTruncated:          more,
		Parts:                parts,
		// also available: UserDefined map[string]string
	}, nil
}

// ListMultipartUploads lists all multipart uploads.
func (gateway *gateway) ListMultipartUploads(ctx context.Context, bucket string, prefix string, keyMarker string, uploadIDMarker string, delimiter string, maxUploads int) (result minio.ListMultipartsInfo, err error) {
	defer mon.Task()(&ctx)(&err)
	defer func() { gateway.log(ctx, err) }()

	project, err := gateway.openProjectMultipart(ctx, getAccessGrant(ctx))
	if err != nil {
		return minio.ListMultipartsInfo{}, err
	}
	defer func() {
		err = errs.Combine(err, project.Close())
	}()

	// TODO maybe this should be checked by project.ListMultipartUploads
	if bucket == "" {
		return minio.ListMultipartsInfo{}, minio.BucketNameInvalid{}
	}

	if delimiter != "" && delimiter != "/" {
		return minio.ListMultipartsInfo{}, minio.UnsupportedDelimiter{Delimiter: delimiter}
	}

	// TODO this should be removed and implemented on satellite side
	defer func() {
		err = checkBucketError(ctx, project, bucket, "", err)
	}()
	recursive := delimiter == ""

	list := project.ListUploads(ctx, bucket, &uplink.ListUploadsOptions{
		Prefix:    prefix,
		Cursor:    keyMarker,
		Recursive: recursive,
		System:    true,
		Custom:    gateway.compatibilityConfig.IncludeCustomMetadataListing,
	})

	startAfter := keyMarker
	var uploads []minio.MultipartInfo
	var prefixes []string

	limit := maxUploads
	for (limit > 0 || maxUploads == 0) && list.Next() {
		limit--
		object := list.Item()
		if object.IsPrefix {
			prefixes = append(prefixes, object.Key)
			continue
		}

		uploads = append(uploads, minioMultipartInfo(bucket, object))

		startAfter = object.Key

	}
	if list.Err() != nil {
		return result, convertMultipartError(list.Err(), bucket, "", "")
	}

	more := list.Next()
	if list.Err() != nil {
		return result, convertMultipartError(list.Err(), bucket, "", "")
	}

	result = minio.ListMultipartsInfo{
		KeyMarker:      keyMarker,
		UploadIDMarker: uploadIDMarker,
		MaxUploads:     maxUploads,
		IsTruncated:    more,
		Uploads:        uploads,
		Prefix:         prefix,
		Delimiter:      delimiter,
		CommonPrefixes: prefixes,
	}
	if more {
		result.NextKeyMarker = startAfter
		// TODO: NextUploadID
	}

	return result, nil
}

func minioMultipartInfo(bucket string, object *uplink.UploadInfo) minio.MultipartInfo {
	if object == nil {
		object = &uplink.UploadInfo{}
	}

	return minio.MultipartInfo{
		Bucket:      bucket,
		Object:      object.Key,
		Initiated:   object.System.Created,
		UploadID:    object.UploadID,
		UserDefined: object.Custom,
	}
}

func multipartUploadETag(parts []minio.CompletePart) (string, error) {
	var hashes []byte
	for _, part := range parts {
		md5, err := hex.DecodeString(canonicalEtag(part.ETag))
		if err != nil {
			hashes = append(hashes, []byte(part.ETag)...)
		} else {
			hashes = append(hashes, md5...)
		}
	}

	/* #nosec G401 */ // ETags aren't security sensitive
	sum := md5.Sum(hashes)
	return hex.EncodeToString(sum[:]) + "-" + strconv.Itoa(len(parts)), nil
}

func canonicalEtag(etag string) string {
	etag = strings.Trim(etag, `"`)
	p := strings.IndexByte(etag, '-')
	if p >= 0 {
		return etag[:p]
	}
	return etag
}

func convertMultipartError(err error, bucket, object, uploadID string) error {
	if errors.Is(err, uplink.ErrUploadIDInvalid) {
		return minio.InvalidUploadID{Bucket: bucket, Object: object, UploadID: uploadID}
	}

	return convertError(err, bucket, object)
}
