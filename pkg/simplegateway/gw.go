// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package simplegateway

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	miniogo "github.com/minio/minio-go/v7"
	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"

	"storj.io/common/memory"
	"storj.io/common/version"
	minio "storj.io/minio/cmd"
	"storj.io/minio/pkg/auth"
	objectlock "storj.io/minio/pkg/bucket/object/lock"
	"storj.io/minio/pkg/madmin"
)

var (
	mon = monkit.Package()

	// ErrObjectTooLarge occurs when attempting to upload an object larger than
	// the configured maxObjectSize on gatewayLayer.
	ErrObjectTooLarge = miniogo.ErrorResponse{
		Code:       "ObjectTooLarge",
		StatusCode: http.StatusBadRequest,
		Message:    "Object is too large",
	}
)

// Gateway is the implementation of cmd.Gateway.
type Gateway struct {
	dataDir       string
	maxObjectSize memory.Size
}

// New creates a new S3 gateway.
func New(dataDir string, maxObjectSize memory.Size) *Gateway {
	return &Gateway{
		dataDir:       dataDir,
		maxObjectSize: maxObjectSize,
	}
}

// Name implements cmd.Gateway.
func (gateway *Gateway) Name() string {
	return "simple"
}

// NewGatewayLayer implements cmd.Gateway.
func (gateway *Gateway) NewGatewayLayer(creds auth.Credentials) (minio.ObjectLayer, error) {
	return &gatewayLayer{
		dataDir:       gateway.dataDir,
		maxObjectSize: gateway.maxObjectSize,
	}, nil
}

// Production implements cmd.Gateway.
func (gateway *Gateway) Production() bool {
	return version.Build.Release
}

type gatewayLayer struct {
	dataDir       string
	fileLocks     sync.Map
	maxObjectSize memory.Size

	minio.GatewayUnsupported
}

// Shutdown is a no-op.
func (layer *gatewayLayer) Shutdown(ctx context.Context) (err error) {
	return nil
}

func (layer *gatewayLayer) StorageInfo(ctx context.Context) (minio.StorageInfo, []error) {
	return minio.StorageInfo{
		Backend: madmin.BackendInfo{
			Type:          madmin.Gateway,
			GatewayOnline: true,
		},
	}, nil
}

func (layer *gatewayLayer) MakeBucketWithLocation(ctx context.Context, bucket string, opts minio.BucketOptions) (err error) {
	defer mon.Task()(&ctx)(&err)

	filePath, err := resolvePath(layer.dataDir, bucket)
	if err != nil {
		return minio.InvalidArgument{Bucket: bucket}
	}

	err = os.Mkdir(filePath, 0755)
	if os.IsExist(err) {
		return minio.BucketAlreadyExists{Bucket: bucket}
	}

	return err
}

func (layer *gatewayLayer) GetBucketInfo(ctx context.Context, bucket string) (bucketInfo minio.BucketInfo, err error) {
	defer mon.Task()(&ctx)(&err)

	filePath, err := resolvePath(layer.dataDir, bucket)
	if err != nil {
		return minio.BucketInfo{}, minio.InvalidArgument{Bucket: bucket}
	}

	info, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		return minio.BucketInfo{}, minio.BucketNotFound{Bucket: bucket}
	}
	if err != nil {
		return minio.BucketInfo{}, err
	}

	return minio.BucketInfo{
		Name:    bucket,
		Created: info.ModTime(),
	}, nil
}

func (layer *gatewayLayer) ListBuckets(ctx context.Context) (items []minio.BucketInfo, err error) {
	return nil, minio.NotImplemented{}
}

func (layer *gatewayLayer) DeleteBucket(ctx context.Context, bucket string, forceDelete bool) (err error) {
	return minio.NotImplemented{}
}

func (layer *gatewayLayer) ListObjects(ctx context.Context, bucket, prefix, marker, delimiter string, maxKeys int) (_ minio.ListObjectsInfo, err error) {
	return minio.ListObjectsInfo{}, minio.NotImplemented{}
}

func (layer *gatewayLayer) ListObjectsV2(ctx context.Context, bucket, prefix, continuationToken, delimiter string, maxKeys int, fetchOwner bool, startAfter string) (_ minio.ListObjectsV2Info, err error) {
	return minio.ListObjectsV2Info{}, minio.NotImplemented{}
}

func (layer *gatewayLayer) GetObjectNInfo(ctx context.Context, bucket, object string, rs *minio.HTTPRangeSpec, h http.Header, lockType minio.LockType, opts minio.ObjectOptions) (reader *minio.GetObjectReader, err error) {
	defer mon.Task()(&ctx)(&err)

	info, content, err := layer.syncReadFile(bucket, object)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, minio.ObjectNotFound{Bucket: bucket, Object: object}
		}
		return nil, err
	}

	objectInfo := minio.ObjectInfo{
		Bucket:  bucket,
		Name:    object,
		Size:    info.Size(),
		ModTime: info.ModTime(),
	}

	return minio.NewGetObjectReaderFromReader(bytes.NewReader(content), objectInfo, opts)
}

func (layer *gatewayLayer) GetObjectInfo(ctx context.Context, bucket, object string, opts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	defer mon.Task()(&ctx)(&err)

	info, err := layer.syncStatFile(bucket, object)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return minio.ObjectInfo{}, minio.ObjectNotFound{Bucket: bucket, Object: object}
		}
		return minio.ObjectInfo{}, err
	}

	return minio.ObjectInfo{
		Bucket:  bucket,
		Name:    object,
		Size:    info.Size(),
		ModTime: info.ModTime(),
	}, nil
}

func (layer *gatewayLayer) PutObject(ctx context.Context, bucket, object string, data *minio.PutObjReader, opts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	defer mon.Task()(&ctx)(&err)

	written, err := layer.syncWriteFile(bucket, object, http.MaxBytesReader(nil, data, layer.maxObjectSize.Int64()))
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		switch {
		case errors.As(err, &maxBytesErr):
			return minio.ObjectInfo{}, ErrObjectTooLarge
		default:
			return minio.ObjectInfo{}, err
		}
	}

	return minio.ObjectInfo{
		Bucket:  bucket,
		Name:    object,
		Size:    written,
		ModTime: time.Now(),
	}, nil
}

func (layer *gatewayLayer) CopyObject(ctx context.Context, srcBucket, srcObject, destBucket, destObject string, srcInfo minio.ObjectInfo, srcOpts, destOpts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	return minio.ObjectInfo{}, minio.NotImplemented{}
}

func (layer *gatewayLayer) DeleteObject(ctx context.Context, bucket, objectPath string, opts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	return minio.ObjectInfo{}, minio.NotImplemented{}
}

func (layer *gatewayLayer) DeleteObjects(ctx context.Context, bucket string, objects []minio.ObjectToDelete, opts minio.ObjectOptions) ([]minio.DeletedObject, []minio.DeleteObjectsError, error) {
	return nil, nil, minio.NotImplemented{}
}

func (layer *gatewayLayer) GetObjectLockConfig(ctx context.Context, bucket string) (*objectlock.Config, error) {
	return nil, minio.NotImplemented{}
}

func (layer *gatewayLayer) SetObjectLockConfig(ctx context.Context, bucket string, config *objectlock.Config) error {
	return minio.NotImplemented{}
}

// even though minio checks for "." and ".." path elements (see setRequestValidityHandler in minio)
// we validate here anyway just in case.
func resolvePath(root, path string) (string, error) {
	if !filepath.IsLocal(path) {
		return "", errs.New("invalid path %s", path)
	}
	return filepath.Join(root, path), nil
}

func (layer *gatewayLayer) getLock(bucket, object string) *sync.Mutex {
	key := path.Join(bucket, object)
	actual, _ := layer.fileLocks.LoadOrStore(key, &sync.Mutex{})
	return actual.(*sync.Mutex)
}

func (layer *gatewayLayer) syncStatFile(bucket, object string) (fs.FileInfo, error) {
	filePath, err := resolvePath(layer.dataDir, path.Join(bucket, object))
	if err != nil {
		return nil, minio.InvalidArgument{Bucket: bucket, Object: object}
	}

	lock := layer.getLock(bucket, object)
	lock.Lock()
	defer lock.Unlock()

	return os.Stat(filePath)
}

func (layer *gatewayLayer) syncReadFile(bucket, object string) (fs.FileInfo, []byte, error) {
	filePath, err := resolvePath(layer.dataDir, path.Join(bucket, object))
	if err != nil {
		return nil, nil, minio.InvalidArgument{Bucket: bucket, Object: object}
	}

	lock := layer.getLock(bucket, object)
	lock.Lock()
	defer lock.Unlock()

	info, err := os.Stat(filePath)
	if err != nil {
		return nil, nil, err
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, err
	}

	return info, content, nil
}

func (layer *gatewayLayer) syncWriteFile(bucket, object string, data io.ReadCloser) (int64, error) {
	filePath, err := resolvePath(layer.dataDir, path.Join(bucket, object))
	if err != nil {
		return 0, minio.InvalidArgument{Bucket: bucket, Object: object}
	}

	lock := layer.getLock(bucket, object)
	lock.Lock()
	defer lock.Unlock()

	content, err := io.ReadAll(data)
	if err != nil {
		return 0, err
	}

	if err := os.WriteFile(filePath, content, 0644); err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			if err := os.MkdirAll(path.Dir(filePath), 0755); err != nil {
				return 0, err
			}
			if err := os.WriteFile(filePath, content, 0644); err != nil {
				return 0, err
			}
		default:
			return 0, err
		}
	}

	return int64(len(content)), nil
}
