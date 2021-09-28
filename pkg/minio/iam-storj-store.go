// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package minio

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/zeebo/errs"

	"storj.io/gateway-mt/pkg/backoff"
	minio "storj.io/minio/cmd"
	"storj.io/minio/cmd/logger"
	"storj.io/minio/pkg/auth"
)

const (
	identityPrefix string = "config/iam/users/"
	authUserSuffix string = "/v1/access"
)

// IAMAuthStore implements ObjectLayer for use by Minio's IAMObjectStore.
// Minio doesn't use the full ObjectLayer interface, so we only implement GetObject.
// If using Minio's Admin APIs, we'd also need DeleteObject, PutObject, and GetObjectInfo.
type IAMAuthStore struct {
	minio.GatewayUnsupported
	authURL   string
	authToken string
	timeout   time.Duration
}

// NewIAMAuthStore creates a Storj-specific Minio IAM store.
func NewIAMAuthStore(authURL, authToken string) (*IAMAuthStore, error) {
	u, err := url.Parse(authURL)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errs.New("unexpected scheme found in endpoint parameter %s", u.Scheme)
	}
	if u.Host == "" {
		return nil, errs.New("host missing in parameter %s", u.Host)
	}
	if !strings.HasSuffix(authURL, authUserSuffix) {
		u.Path = path.Join(u.Path, authUserSuffix)
	}

	return &IAMAuthStore{authURL: u.String(), authToken: authToken, timeout: 5 * time.Second}, nil
}

// objectPathToUser extracts the user from the object identity path.
// For example: "config/iam/users/myuser/identity.json" => "myuser".
func objectPathToUser(key string) string {
	// remove the "config/iam/users/" prefix, leaving "myuser/identity.json"
	user := strings.TrimPrefix(key, identityPrefix)

	// remove the element after the user, e.g. "myuser/identity.json" => "myuser/"
	user = strings.TrimSuffix(user, path.Base(key))

	// clean the result, e.g. remove trailing "/"
	user = path.Clean(user)

	// path.Base() returns "." or "/" in some cases when the key is invalid.
	// in those cases, we just want to return an empty string.
	if user == "." || user == "/" {
		user = ""
	}

	return user
}

// GetObject is called by Minio's IAMObjectStore, and in turn queries the Auth Service.
// If passed an iamConfigUsers style objectPath, it returns a JSON-serialized UserIdentity.
func (iamOS *IAMAuthStore) GetObject(ctx context.Context, bucketName, objectPath string, startOffset, length int64, writer io.Writer, etag string, opts minio.ObjectOptions) (err error) {
	defer func() { logger.LogIf(ctx, err) }()

	user := objectPathToUser(objectPath)
	if user == "" {
		return minio.ObjectNotFound{Bucket: bucketName, Object: objectPath}
	}

	// path.Join() doesn't work with the protocol attached to the auth URL
	// as it assumes it's one of the path elements and replaces double slashes
	// with a single slash. Since authURL is already parsed, all we do here
	// is suffix the user.
	reqURL := iamOS.authURL + "/" + user

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+iamOS.authToken)
	req.Header.Set("Forwarded", "for="+logger.GetReqInfo(ctx).RemoteHost)

	// TODO (wthorp):  Handle Transports config holistically instead; this is here to pass Minio era tests.
	httpClient := &http.Client{Transport: &http.Transport{ResponseHeaderTimeout: iamOS.timeout}}
	delay := backoff.ExponentialBackoff{Min: 100 * time.Millisecond, Max: iamOS.timeout}

	var response struct {
		AccessGrant string `json:"access_grant"`
		SecretKey   string `json:"secret_key"`
		Public      bool   `json:"public"`
	}

	for {
		resp, err := httpClient.Do(req)
		if err != nil {
			if !delay.Maxed() {
				if err := delay.Wait(ctx); err != nil {
					return err
				}
				continue
			}
			return err
		}

		// Use an anonymous function for deferring the response close before the
		// next retry and not pilling it up when the method returns.
		retry, err := func() (retry bool, _ error) {
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode == http.StatusInternalServerError {
				return true, nil // auth only returns this for unexpected issues
			}

			if resp.StatusCode != http.StatusOK {
				return false, fmt.Errorf("invalid status code: %d", resp.StatusCode)
			}

			if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
				if !delay.Maxed() {
					return true, nil
				}
				return false, err
			}
			return false, nil
		}()

		if retry {
			if err := delay.Wait(ctx); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		// TODO: We need to eventually expire credentials.
		// Using Store.watch()?  Using Credentials.Expiration?
		return json.NewEncoder(writer).Encode(minio.UserIdentity{
			Version: 1,
			Credentials: auth.Credentials{
				AccessKey:   user,
				AccessGrant: response.AccessGrant,
				SecretKey:   response.SecretKey,
				Status:      "on",
			},
		})
	}
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
