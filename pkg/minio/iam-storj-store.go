// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package minio

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"storj.io/gateway-mt/pkg/authclient"
	"storj.io/gateway-mt/pkg/server/middleware"
	minio "storj.io/minio/cmd"
	"storj.io/minio/cmd/logger"
	"storj.io/minio/pkg/auth"
)

const identityPrefix string = "config/iam/users/"
const identitySuffix string = "/identity.json"

// IAMAuthStore implements ObjectLayer for use by Minio's IAMObjectStore.
// Minio doesn't use the full ObjectLayer interface, so we only implement GetObject.
// If using Minio's Admin APIs, we'd also need DeleteObject, PutObject, and GetObjectInfo.
type IAMAuthStore struct {
	NotImplementedObjectStore
}

// objectPathToUser extracts the user from the object identity path.
// For example: "config/iam/users/myuser/identity.json" => "myuser".
func objectPathToUser(key string) string {
	// remove the "config/iam/users/" prefix, leaving "myuser/identity.json"
	if !strings.HasPrefix(key, identityPrefix) {
		return ""
	}
	user := strings.TrimPrefix(key, identityPrefix)

	// remove the element after the user, e.g. "myuser/identity.json" => "myuser"
	if !strings.HasSuffix(key, identitySuffix) {
		return ""
	}
	user = strings.TrimSuffix(user, identitySuffix)
	return user
}

// GetObject is called by Minio's IAMObjectStore, and in turn queries the Auth Service.
// If passed an iamConfigUsers style objectPath, it returns a JSON-serialized UserIdentity.
func (iamOS *IAMAuthStore) GetObject(ctx context.Context, bucketName, objectPath string, startOffset, length int64, writer io.Writer, etag string, opts minio.ObjectOptions) (err error) {
	// filter out non-user requests (policy, etc).
	user := objectPathToUser(objectPath)
	if user == "" {
		return minio.ObjectNotFound{Bucket: bucketName, Object: objectPath}
	}
	defer func() { logger.LogIf(ctx, err) }()

	// Get credentials from request context.
	// Note that this requires altering Minio to pass in the request context.
	// See https://github.com/storj/minio/commit/df6c27823c8af00578433d49edba930d1e408c49
	credentials := middleware.GetAccess(ctx)
	if credentials == nil {
		// TODO: is there a better error option here?
		return minio.ObjectNotFound{Bucket: bucketName, Object: objectPath}
	}
	if credentials.Error != nil {
		var httpError authclient.HTTPError
		if errors.As(credentials.Error, &httpError) {
			if httpError == http.StatusUnauthorized {
				return minio.ObjectNotFound{Bucket: bucketName, Object: objectPath}
			}
		}
		return credentials.Error
	}

	// TODO: We need to eventually expire credentials.
	// Using Store.watch()?  Using Credentials.Expiration?
	return json.NewEncoder(writer).Encode(minio.UserIdentity{
		Version: 1,
		Credentials: auth.Credentials{
			AccessKey: user,
			SecretKey: credentials.SecretKey,
			Status:    "on",
		},
	})
}

// NotImplementedObjectStore implements the ObjectLayer interface, but returns NotImplemented for all receivers.
type NotImplementedObjectStore struct {
	minio.GatewayUnsupported
}

// GetObject is unimplemented, but required to meet the ObjectLayer interface.
func (iamOS *NotImplementedObjectStore) GetObject(ctx context.Context, bucketName, objectPath string, startOffset, length int64, writer io.Writer, etag string, opts minio.ObjectOptions) (err error) {
	return minio.NotImplemented{}
}

// DeleteBucket is unimplemented, but required to meet the ObjectLayer interface.
func (iamOS *NotImplementedObjectStore) DeleteBucket(ctx context.Context, bucket string, forceDelete bool) (err error) {
	return minio.NotImplemented{}
}

// DeleteObject is unimplemented, but required to meet the ObjectLayer interface.
func (iamOS *NotImplementedObjectStore) DeleteObject(ctx context.Context, bucket, object string, opts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	return minio.ObjectInfo{Bucket: bucket, Name: object}, minio.NotImplemented{}
}

// DeleteObjects is unimplemented, but required to meet the ObjectLayer interface.
func (iamOS *NotImplementedObjectStore) DeleteObjects(ctx context.Context, bucket string, objects []minio.ObjectToDelete, opts minio.ObjectOptions) ([]minio.DeletedObject, []error) {
	return []minio.DeletedObject{}, []error{minio.NotImplemented{}}
}

// GetBucketInfo is unimplemented, but required to meet the ObjectLayer interface.
func (iamOS *NotImplementedObjectStore) GetBucketInfo(ctx context.Context, bucket string) (bucketInfo minio.BucketInfo, err error) {
	return minio.BucketInfo{}, minio.NotImplemented{}
}

// GetObjectInfo is unimplemented, but required to meet the ObjectLayer interface.
func (iamOS *NotImplementedObjectStore) GetObjectInfo(ctx context.Context, bucket, object string, opts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	return minio.ObjectInfo{Bucket: bucket, Name: object}, minio.NotImplemented{}
}

// GetObjectNInfo is unimplemented, but required to meet the ObjectLayer interface.
func (iamOS *NotImplementedObjectStore) GetObjectNInfo(ctx context.Context, bucket, object string, rs *minio.HTTPRangeSpec, h http.Header, lockType minio.LockType, opts minio.ObjectOptions) (reader *minio.GetObjectReader, err error) {
	return nil, minio.NotImplemented{}
}

// ListBuckets is unimplemented, but required to meet the ObjectLayer interface.
func (iamOS *NotImplementedObjectStore) ListBuckets(ctx context.Context) (buckets []minio.BucketInfo, err error) {
	return []minio.BucketInfo{}, minio.NotImplemented{}
}

// ListObjects is unimplemented, but required to meet the ObjectLayer interface.
func (iamOS *NotImplementedObjectStore) ListObjects(ctx context.Context, bucket, prefix, marker, delimiter string, maxKeys int) (result minio.ListObjectsInfo, err error) {
	return minio.ListObjectsInfo{}, minio.NotImplemented{}
}

// MakeBucketWithLocation is unimplemented, but required to meet the ObjectLayer interface.
func (iamOS *NotImplementedObjectStore) MakeBucketWithLocation(ctx context.Context, bucket string, opts minio.BucketOptions) error {
	return minio.NotImplemented{}
}

// PutObject is unimplemented, but required to meet the ObjectLayer interface.
func (iamOS *NotImplementedObjectStore) PutObject(ctx context.Context, bucket, object string, data *minio.PutObjReader, opts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	return minio.ObjectInfo{Bucket: bucket, Name: object}, minio.NotImplemented{}
}

// Shutdown is unimplemented, but required to meet the ObjectLayer interface.
func (iamOS *NotImplementedObjectStore) Shutdown(context.Context) error {
	return minio.NotImplemented{}
}

// StorageInfo is unimplemented, but required to meet the ObjectLayer interface.
func (iamOS *NotImplementedObjectStore) StorageInfo(ctx context.Context, local bool) (minio.StorageInfo, []error) {
	return minio.StorageInfo{}, []error{minio.NotImplemented{}}
}
