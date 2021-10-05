// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package minio

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"storj.io/gateway-mt/pkg/authclient"
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
	minio.GatewayUnsupported
	authClient *authclient.AuthClient
}

// NewIAMAuthStore creates a Storj-specific Minio IAM store.
func NewIAMAuthStore(authURL, authToken string) (*IAMAuthStore, error) {
	u, err := url.Parse(authURL)
	if err != nil {
		return nil, err
	}
	authClient, err := authclient.New(u, authToken, time.Second*5)
	if err != nil {
		return nil, err
	}
	return &IAMAuthStore{authClient: authClient}, nil
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
	user := objectPathToUser(objectPath)
	if user == "" {
		return minio.ObjectNotFound{Bucket: bucketName, Object: objectPath}
	}

	defer func() { logger.LogIf(ctx, err) }()
	authResponse, err := iamOS.authClient.GetAccess(ctx, user, logger.GetReqInfo(ctx).RemoteHost)
	if err != nil {
		var httpError authclient.HTTPError
		if errors.As(err, &httpError) {
			if httpError == http.StatusUnauthorized {
				return minio.ObjectNotFound{Bucket: bucketName, Object: objectPath}
			}
		}
		return err
	}

	// TODO: We need to eventually expire credentials.
	// Using Store.watch()?  Using Credentials.Expiration?
	return json.NewEncoder(writer).Encode(minio.UserIdentity{
		Version: 1,
		Credentials: auth.Credentials{
			AccessKey:   user,
			AccessGrant: authResponse.AccessGrant,
			SecretKey:   authResponse.SecretKey,
			Status:      "on",
		},
	})
}

// DeleteBucket is unimplemented, but required to meet the ObjectLayer interface.
func (iamOS *IAMAuthStore) DeleteBucket(ctx context.Context, bucket string, forceDelete bool) (err error) {
	return minio.NotImplemented{}
}

// DeleteObject is unimplemented, but required to meet the ObjectLayer interface.
func (iamOS *IAMAuthStore) DeleteObject(ctx context.Context, bucket, object string, opts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	return minio.ObjectInfo{Bucket: bucket, Name: object}, minio.NotImplemented{}
}

// DeleteObjects is unimplemented, but required to meet the ObjectLayer interface.
func (iamOS *IAMAuthStore) DeleteObjects(ctx context.Context, bucket string, objects []minio.ObjectToDelete, opts minio.ObjectOptions) ([]minio.DeletedObject, []error) {
	return []minio.DeletedObject{}, []error{minio.NotImplemented{}}
}

// GetBucketInfo is unimplemented, but required to meet the ObjectLayer interface.
func (iamOS *IAMAuthStore) GetBucketInfo(ctx context.Context, bucket string) (bucketInfo minio.BucketInfo, err error) {
	return minio.BucketInfo{}, minio.NotImplemented{}
}

// GetObjectInfo is unimplemented, but required to meet the ObjectLayer interface.
func (iamOS *IAMAuthStore) GetObjectInfo(ctx context.Context, bucket, object string, opts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	return minio.ObjectInfo{Bucket: bucket, Name: object}, minio.NotImplemented{}
}

// GetObjectNInfo is unimplemented, but required to meet the ObjectLayer interface.
func (iamOS *IAMAuthStore) GetObjectNInfo(ctx context.Context, bucket, object string, rs *minio.HTTPRangeSpec, h http.Header, lockType minio.LockType, opts minio.ObjectOptions) (reader *minio.GetObjectReader, err error) {
	return nil, minio.NotImplemented{}
}

// ListBuckets is unimplemented, but required to meet the ObjectLayer interface.
func (iamOS *IAMAuthStore) ListBuckets(ctx context.Context) (buckets []minio.BucketInfo, err error) {
	return []minio.BucketInfo{}, minio.NotImplemented{}
}

// ListObjects is unimplemented, but required to meet the ObjectLayer interface.
func (iamOS *IAMAuthStore) ListObjects(ctx context.Context, bucket, prefix, marker, delimiter string, maxKeys int) (result minio.ListObjectsInfo, err error) {
	return minio.ListObjectsInfo{}, minio.NotImplemented{}
}

// MakeBucketWithLocation is unimplemented, but required to meet the ObjectLayer interface.
func (iamOS *IAMAuthStore) MakeBucketWithLocation(ctx context.Context, bucket string, opts minio.BucketOptions) error {
	return minio.NotImplemented{}
}

// PutObject is unimplemented, but required to meet the ObjectLayer interface.
func (iamOS *IAMAuthStore) PutObject(ctx context.Context, bucket, object string, data *minio.PutObjReader, opts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	return minio.ObjectInfo{Bucket: bucket, Name: object}, minio.NotImplemented{}
}

// Shutdown is unimplemented, but required to meet the ObjectLayer interface.
func (iamOS *IAMAuthStore) Shutdown(context.Context) error {
	return minio.NotImplemented{}
}

// StorageInfo is unimplemented, but required to meet the ObjectLayer interface.
func (iamOS *IAMAuthStore) StorageInfo(ctx context.Context, local bool) (minio.StorageInfo, []error) {
	return minio.StorageInfo{}, []error{minio.NotImplemented{}}
}
