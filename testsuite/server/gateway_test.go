// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package server_test

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcutil/base58"
	minio "github.com/minio/minio/cmd"
	xhttp "github.com/minio/minio/cmd/http"
	"github.com/minio/minio/cmd/logger"
	"github.com/minio/minio/pkg/hash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"storj.io/common/memory"
	"storj.io/common/pb"
	"storj.io/common/rpc"
	"storj.io/common/storj"
	"storj.io/common/testcontext"
	"storj.io/common/testrand"
	"storj.io/gateway-mt/pkg/server"
	"storj.io/storj/private/testplanet"
	"storj.io/uplink"
)

const (
	testBucket = "test-bucket"
	testFile   = "test-file"
	testFile2  = "test-file-2"
	testFile3  = "test-file-3"
	destBucket = "dest-bucket"
	destFile   = "dest-file"
)

func TestMakeBucketWithLocation(t *testing.T) {
	t.Parallel()

	runTest(t, func(t *testing.T, ctx context.Context, layer minio.ObjectLayer, project *uplink.Project) {
		// Check the error when creating bucket with empty name
		err := layer.MakeBucketWithLocation(ctx, "", minio.BucketOptions{})
		assert.Equal(t, minio.BucketNameInvalid{}, err)

		// Create a bucket with the Minio API
		err = layer.MakeBucketWithLocation(ctx, testBucket, minio.BucketOptions{})
		assert.NoError(t, err)

		// Check that the bucket is created using the Uplink API
		bucket, err := project.StatBucket(ctx, testBucket)
		require.NoError(t, err)
		assert.Equal(t, testBucket, bucket.Name)
		assert.True(t, time.Since(bucket.Created) < 1*time.Minute)

		// Check the error when trying to create an existing bucket
		err = layer.MakeBucketWithLocation(ctx, testBucket, minio.BucketOptions{})
		assert.Equal(t, minio.BucketAlreadyExists{Bucket: testBucket}, err)
	})
}

func TestGetBucketInfo(t *testing.T) {
	t.Parallel()

	runTest(t, func(t *testing.T, ctx context.Context, layer minio.ObjectLayer, project *uplink.Project) {
		// Check the error when getting info about bucket with empty name
		_, err := layer.GetBucketInfo(ctx, "")
		assert.Equal(t, minio.BucketNameInvalid{}, err)

		// Check the error when getting info about non-existing bucket
		_, err = layer.GetBucketInfo(ctx, testBucket)
		assert.Equal(t, minio.BucketNotFound{Bucket: testBucket}, err)

		// Create the bucket using the Uplink API
		info, err := project.CreateBucket(ctx, testBucket)
		assert.NoError(t, err)

		// Check the bucket info using the Minio API
		bucket, err := layer.GetBucketInfo(ctx, testBucket)
		if assert.NoError(t, err) {
			assert.Equal(t, testBucket, bucket.Name)
			assert.Equal(t, info.Created, bucket.Created)
		}
	})
}

func maybeAbortPartUpload(t *testing.T, err error, part *uplink.PartUpload) {
	if err != nil {
		assert.NoError(t, part.Abort())
	}
}

func maybeAbortMultipartUpload(ctx context.Context, t *testing.T, err error, project *uplink.Project, bucket, key, uploadID string) {
	if err != nil {
		assert.NoError(t, err, project.AbortUpload(ctx, bucket, key, uploadID))
	}
}

func addPendingMultipartUpload(ctx context.Context, t *testing.T, project *uplink.Project, bucket *uplink.Bucket) {
	for i := 0; i < 2; i++ {
		upload, err := project.BeginUpload(ctx, bucket.Name, testFile2, nil)
		require.NoError(t, err)

		t.Logf("%d: started upload of %s with ID=%s", i, upload.Key, upload.UploadID)

		for j := uint32(0); j < 3; j++ {
			part, err := project.UploadPart(ctx, bucket.Name, testFile2, upload.UploadID, j)
			maybeAbortPartUpload(t, err, part)
			maybeAbortMultipartUpload(ctx, t, err, project, bucket.Name, testFile2, upload.UploadID)
			require.NoError(t, err)

			t.Logf("%d/%d: started part upload", i, part.Info().PartNumber)

			_, err = part.Write(make([]byte, 4*memory.KiB))
			maybeAbortPartUpload(t, err, part)
			maybeAbortMultipartUpload(ctx, t, err, project, bucket.Name, testFile2, upload.UploadID)
			require.NoError(t, err)

			err = part.Commit()
			maybeAbortPartUpload(t, err, part)
			maybeAbortMultipartUpload(ctx, t, err, project, bucket.Name, testFile2, upload.UploadID)
			require.NoError(t, err)

			t.Logf("%d/%d: finished part upload (uploaded %d bytes)", i, part.Info().PartNumber, part.Info().Size)
		}

		t.Logf("%d: finished uploading parts of %s (ID=%s)", i, upload.Key, upload.UploadID)
	}
}

func TestDeleteBucket(t *testing.T) {
	t.Parallel()

	runTest(t, func(t *testing.T, ctx context.Context, layer minio.ObjectLayer, project *uplink.Project) {
		{
			// Check the error when deleting bucket with empty name
			err := layer.DeleteBucket(ctx, "", false)
			assert.Equal(t, minio.BucketNameInvalid{}, err)

			// Check the error when deleting non-existing bucket
			err = layer.DeleteBucket(ctx, testBucket, false)
			assert.Equal(t, minio.BucketNotFound{Bucket: testBucket}, err)

			// Create a bucket with a file using the Uplink API
			bucket, err := project.CreateBucket(ctx, testBucket)
			assert.NoError(t, err)

			_, err = createFile(ctx, project, bucket.Name, testFile, nil, nil)
			assert.NoError(t, err)

			// Check the error when deleting non-empty bucket
			err = layer.DeleteBucket(ctx, testBucket, false)
			assert.Equal(t, minio.BucketNotEmpty{Bucket: testBucket}, err)

			// Delete the file using the Uplink API, so the bucket becomes empty
			_, err = project.DeleteObject(ctx, bucket.Name, testFile)
			assert.NoError(t, err)

			// Delete the bucket info using the Minio API
			err = layer.DeleteBucket(ctx, testBucket, false)
			assert.NoError(t, err)

			// Check that the bucket is deleted using the Uplink API
			_, err = project.StatBucket(ctx, testBucket)
			assert.True(t, errors.Is(err, uplink.ErrBucketNotFound))
		}
		{
			// Create a bucket with a file using the Uplink API
			bucket, err := project.CreateBucket(ctx, testBucket)
			assert.NoError(t, err)

			_, err = createFile(ctx, project, bucket.Name, testFile, nil, nil)
			assert.NoError(t, err)

			// Check deleting bucket with force flag
			err = layer.DeleteBucket(ctx, testBucket, true)
			assert.NoError(t, err)

			// Check that the bucket is deleted using the Uplink API
			_, err = project.StatBucket(ctx, testBucket)
			assert.True(t, errors.Is(err, uplink.ErrBucketNotFound))

			// Check the error when deleting non-existing bucket
			err = layer.DeleteBucket(ctx, testBucket, true)
			assert.Equal(t, minio.BucketNotFound{Bucket: testBucket}, err)
		}
		{
			// Test deletion of the empty bucket with pending multipart uploads.
			bucket, err := project.CreateBucket(ctx, testBucket)
			assert.NoError(t, err)

			addPendingMultipartUpload(ctx, t, project, bucket)

			// Initiate bucket deletion with forceDelete=false because this flag
			// isn't passed from non-minio clients to the bucket deletion
			// handler anyway.
			assert.NoError(t, layer.DeleteBucket(ctx, bucket.Name, false))
		}
		{
			// Test deletion of the empty bucket with pending multipart uploads,
			// but there's an additional non-pending object.
			bucket, err := project.CreateBucket(ctx, testBucket)
			assert.NoError(t, err)

			_, err = createFile(ctx, project, bucket.Name, testFile, nil, nil)
			assert.NoError(t, err)

			addPendingMultipartUpload(ctx, t, project, bucket)

			assert.ErrorIs(t, layer.DeleteBucket(ctx, bucket.Name, false), minio.BucketNotEmpty{Bucket: bucket.Name})
		}
	})
}

func TestListBuckets(t *testing.T) {
	t.Parallel()

	runTest(t, func(t *testing.T, ctx context.Context, layer minio.ObjectLayer, project *uplink.Project) {
		// Check that empty list is return if no buckets exist yet
		bucketInfos, err := layer.ListBuckets(ctx)
		assert.NoError(t, err)
		assert.Empty(t, bucketInfos)

		// Create all expected buckets using the Uplink API
		bucketNames := []string{"bucket-1", "bucket-2", "bucket-3"}
		buckets := make([]*uplink.Bucket, len(bucketNames))
		for i, bucketName := range bucketNames {
			bucket, err := project.CreateBucket(ctx, bucketName)
			buckets[i] = bucket
			assert.NoError(t, err)
		}

		// Check that the expected buckets can be listed using the Minio API
		bucketInfos, err = layer.ListBuckets(ctx)
		if assert.NoError(t, err) {
			assert.Equal(t, len(bucketNames), len(bucketInfos))
			for i, bucketInfo := range bucketInfos {
				assert.Equal(t, bucketNames[i], bucketInfo.Name)
				assert.Equal(t, buckets[i].Created, bucketInfo.Created)
			}
		}
	})
}

func TestPutObject(t *testing.T) {
	t.Parallel()

	runTest(t, func(t *testing.T, ctx context.Context, layer minio.ObjectLayer, project *uplink.Project) {
		hashReader, err := hash.NewReader(bytes.NewReader([]byte("test")),
			int64(len("test")),
			"098f6bcd4621d373cade4e832627b4f6",
			"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
			int64(len("test")),
			true,
		)
		require.NoError(t, err)
		data := minio.NewPutObjReader(hashReader, nil, nil)

		metadata := map[string]string{
			"content-type":         "media/foo",
			"key1":                 "value1",
			"key2":                 "value2",
			xhttp.AmzObjectTagging: "key3=value3&key4=value4",
		}

		expectedMetaInfo := pb.SerializableMeta{
			ContentType: metadata["content-type"],
			UserDefined: map[string]string{
				"key1":    metadata["key1"],
				"key2":    metadata["key2"],
				"s3:tags": "key3=value3&key4=value4",
			},
		}

		// Check the error when putting an object to a bucket with empty name
		_, err = layer.PutObject(ctx, "", "", nil, minio.ObjectOptions{})
		assert.Equal(t, minio.BucketNameInvalid{}, err)

		// Check the error when putting an object to a non-existing bucket
		_, err = layer.PutObject(ctx, testBucket, testFile, nil, minio.ObjectOptions{UserDefined: metadata})
		assert.Equal(t, minio.BucketNotFound{Bucket: testBucket}, err)

		// Create the bucket using the Uplink API
		testBucketInfo, err := project.CreateBucket(ctx, testBucket)
		assert.NoError(t, err)

		// Check the error when putting an object with empty name
		_, err = layer.PutObject(ctx, testBucket, "", nil, minio.ObjectOptions{})
		assert.Equal(t, minio.ObjectNameInvalid{Bucket: testBucket}, err)

		// Put the object using the Minio API
		info, err := layer.PutObject(ctx, testBucket, testFile, data, minio.ObjectOptions{UserDefined: metadata})
		if assert.NoError(t, err) {
			assert.Equal(t, testFile, info.Name)
			assert.Equal(t, testBucket, info.Bucket)
			assert.False(t, info.IsDir)
			assert.True(t, time.Since(info.ModTime) < 1*time.Minute)
			assert.Equal(t, data.Size(), info.Size)
			assert.NotEmpty(t, info.ETag)
			assert.Equal(t, expectedMetaInfo.ContentType, info.ContentType)

			expectedMetaInfo.UserDefined["s3:etag"] = info.ETag
			expectedMetaInfo.UserDefined["content-type"] = info.ContentType
			assert.Equal(t, expectedMetaInfo.UserDefined, info.UserDefined)
		}

		// Check that the object is uploaded using the Uplink API
		obj, err := project.StatObject(ctx, testBucketInfo.Name, testFile)
		if assert.NoError(t, err) {
			assert.Equal(t, testFile, obj.Key)
			assert.False(t, obj.IsPrefix)

			// TODO upload.Info() is using StreamID creation time but this value is different
			// than last segment creation time, CommitObject request should return latest info
			// about object and those values should be used with upload.Info()
			// This should be working after final fix
			// assert.Equal(t, info.ModTime, obj.Info.Created)
			assert.WithinDuration(t, info.ModTime, obj.System.Created, 1*time.Second)

			assert.Equal(t, info.Size, obj.System.ContentLength)
			// TODO disabled until we will store ETag with object
			// assert.Equal(t, info.ETag, hex.EncodeToString(obj.Checksum))
			assert.Equal(t, info.ContentType, obj.Custom["content-type"])
			assert.EqualValues(t, info.UserDefined, obj.Custom)
		}
	})
}

func TestPutObjectZeroBytes(t *testing.T) {
	t.Parallel()

	runTest(t, func(t *testing.T, ctx context.Context, layer minio.ObjectLayer, project *uplink.Project) {
		bucket, err := project.CreateBucket(ctx, testBucket)
		require.NoError(t, err)

		h, err := hash.NewReader(
			bytes.NewReader(make([]byte, 0)),
			0,
			"d41d8cd98f00b204e9800998ecf8427e",
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			0,
			true)
		require.NoError(t, err)

		r := minio.NewPutObjReader(h, nil, nil)

		opts := minio.ObjectOptions{
			UserDefined: make(map[string]string),
		}

		obj, err := layer.PutObject(ctx, bucket.Name, testFile, r, opts)
		require.NoError(t, err)

		assert.Zero(t, obj.Size)

		downloaded, err := project.DownloadObject(ctx, obj.Bucket, obj.Name, nil)
		require.NoError(t, err)

		_, err = downloaded.Read(make([]byte, 1))
		assert.ErrorIs(t, err, io.EOF)

		assert.Zero(t, downloaded.Info().System.ContentLength)

		require.NoError(t, downloaded.Close())
	})
}

func TestGetObjectInfo(t *testing.T) {
	t.Parallel()

	runTest(t, func(t *testing.T, ctx context.Context, layer minio.ObjectLayer, project *uplink.Project) {
		// Check the error when getting an object from a bucket with empty name
		_, err := layer.GetObjectInfo(ctx, "", "", minio.ObjectOptions{})
		assert.Equal(t, minio.BucketNameInvalid{}, err)

		// Check the error when getting an object from non-existing bucket
		_, err = layer.GetObjectInfo(ctx, testBucket, testFile, minio.ObjectOptions{})
		assert.Equal(t, minio.BucketNotFound{Bucket: testBucket}, err)

		// Create the bucket using the Uplink API
		testBucketInfo, err := project.CreateBucket(ctx, testBucket)
		assert.NoError(t, err)

		// Check the error when getting an object with empty name
		_, err = layer.GetObjectInfo(ctx, testBucket, "", minio.ObjectOptions{})
		assert.Equal(t, minio.ObjectNameInvalid{Bucket: testBucket}, err)

		// Check the error when getting a non-existing object
		_, err = layer.GetObjectInfo(ctx, testBucket, testFile, minio.ObjectOptions{})
		assert.Equal(t, minio.ObjectNotFound{Bucket: testBucket, Object: testFile}, err)

		// Create the object using the Uplink API
		metadata := map[string]string{
			"content-type": "text/plain",
			"key1":         "value1",
			"key2":         "value2",
		}
		obj, err := createFile(ctx, project, testBucketInfo.Name, testFile, []byte("test"), metadata)
		assert.NoError(t, err)

		// Get the object info using the Minio API
		info, err := layer.GetObjectInfo(ctx, testBucket, testFile, minio.ObjectOptions{})
		if assert.NoError(t, err) {
			assert.Equal(t, testFile, info.Name)
			assert.Equal(t, testBucket, info.Bucket)
			assert.False(t, info.IsDir)

			// TODO upload.Info() is using StreamID creation time but this value is different
			// than last segment creation time, CommitObject request should return latest info
			// about object and those values should be used with upload.Info()
			// This should be working after final fix
			// assert.Equal(t, info.ModTime, obj.Info.Created)
			assert.WithinDuration(t, info.ModTime, obj.System.Created, 1*time.Second)

			assert.Equal(t, obj.System.ContentLength, info.Size)
			assert.Equal(t, obj.Custom["s3:etag"], info.ETag)
			assert.Equal(t, "text/plain", info.ContentType)
			assert.Equal(t, metadata, info.UserDefined)
		}
	})
}

func TestGetObjectNInfo(t *testing.T) {
	t.Parallel()

	runTest(t, func(t *testing.T, ctx context.Context, layer minio.ObjectLayer, project *uplink.Project) {
		// Check the error when getting an object from a bucket with empty name
		_, err := layer.GetObjectNInfo(ctx, "", "", nil, nil, 0, minio.ObjectOptions{})
		assert.Equal(t, minio.BucketNameInvalid{}, err)

		// Check the error when getting an object from non-existing bucket
		_, err = layer.GetObjectNInfo(ctx, testBucket, testFile, nil, nil, 0, minio.ObjectOptions{})
		assert.Equal(t, minio.BucketNotFound{Bucket: testBucket}, err)

		// Create the bucket using the Uplink API
		testBucketInfo, err := project.CreateBucket(ctx, testBucket)
		assert.NoError(t, err)

		// Check the error when getting an object with empty name
		_, err = layer.GetObjectNInfo(ctx, testBucket, "", nil, nil, 0, minio.ObjectOptions{})
		assert.Equal(t, minio.ObjectNameInvalid{Bucket: testBucket}, err)

		// Check the error when getting a non-existing object
		_, err = layer.GetObjectNInfo(ctx, testBucket, testFile, nil, nil, 0, minio.ObjectOptions{})
		assert.Equal(t, minio.ObjectNotFound{Bucket: testBucket, Object: testFile}, err)

		// Create the object using the Uplink API
		metadata := map[string]string{
			"content-type": "text/plain",
			"key1":         "value1",
			"key2":         "value2",
		}
		_, err = createFile(ctx, project, testBucketInfo.Name, testFile, []byte("abcdef"), metadata)
		assert.NoError(t, err)

		for i, tt := range []struct {
			rangeSpec *minio.HTTPRangeSpec
			substr    string
			err       bool
		}{
			{rangeSpec: nil, substr: "abcdef"},
			{rangeSpec: &minio.HTTPRangeSpec{Start: 0, End: 0}, substr: "a"},
			{rangeSpec: &minio.HTTPRangeSpec{Start: 3, End: 3}, substr: "d"},
			{rangeSpec: &minio.HTTPRangeSpec{Start: 0, End: -1}, substr: "abcdef"},
			{rangeSpec: &minio.HTTPRangeSpec{Start: 0, End: 100}, substr: "abcdef"},
			{rangeSpec: &minio.HTTPRangeSpec{Start: 3, End: -1}, substr: "def"},
			{rangeSpec: &minio.HTTPRangeSpec{Start: 3, End: 100}, substr: "def"},
			{rangeSpec: &minio.HTTPRangeSpec{Start: 0, End: 5}, substr: "abcdef"},
			{rangeSpec: &minio.HTTPRangeSpec{Start: 0, End: 4}, substr: "abcde"},
			{rangeSpec: &minio.HTTPRangeSpec{Start: 0, End: 3}, substr: "abcd"},
			{rangeSpec: &minio.HTTPRangeSpec{Start: 1, End: 4}, substr: "bcde"},
			{rangeSpec: &minio.HTTPRangeSpec{Start: 2, End: 5}, substr: "cdef"},
			{rangeSpec: &minio.HTTPRangeSpec{IsSuffixLength: true, Start: 0, End: -1}, substr: ""},
			{rangeSpec: &minio.HTTPRangeSpec{IsSuffixLength: true, Start: -2, End: -1}, substr: "ef"},
			{rangeSpec: &minio.HTTPRangeSpec{IsSuffixLength: true, Start: -100, End: -1}, substr: "abcdef"},
			{rangeSpec: &minio.HTTPRangeSpec{Start: -1, End: 3}, err: true},
			{rangeSpec: &minio.HTTPRangeSpec{Start: 0, End: -2}, err: true},
			{rangeSpec: &minio.HTTPRangeSpec{IsSuffixLength: true, Start: 1}, err: true},
		} {
			errTag := fmt.Sprintf("%d. %v", i, tt)

			// Get the object info using the Minio API
			reader, err := layer.GetObjectNInfo(ctx, testBucket, testFile, tt.rangeSpec, nil, 0, minio.ObjectOptions{})

			if tt.err {
				assert.Error(t, err, errTag)
			} else if assert.NoError(t, err) {
				data, err := ioutil.ReadAll(reader)
				assert.NoError(t, err, errTag)

				err = reader.Close()
				assert.NoError(t, err, errTag)

				assert.Equal(t, tt.substr, string(data), errTag)
			}
		}
	})
}

func TestGetObject(t *testing.T) {
	t.Parallel()

	runTest(t, func(t *testing.T, ctx context.Context, layer minio.ObjectLayer, project *uplink.Project) {
		// Check the error when getting an object from a bucket with empty name
		err := layer.GetObject(ctx, "", "", 0, 0, nil, "", minio.ObjectOptions{})
		assert.Equal(t, minio.BucketNameInvalid{}, err)

		// Check the error when getting an object from non-existing bucket
		err = layer.GetObject(ctx, testBucket, testFile, 0, 0, nil, "", minio.ObjectOptions{})
		assert.Equal(t, minio.BucketNotFound{Bucket: testBucket}, err)

		// Create the bucket using the Uplink API
		testBucketInfo, err := project.CreateBucket(ctx, testBucket)
		assert.NoError(t, err)

		// Check the error when getting an object with empty name
		err = layer.GetObject(ctx, testBucket, "", 0, 0, nil, "", minio.ObjectOptions{})
		assert.Equal(t, minio.ObjectNameInvalid{Bucket: testBucket}, err)

		// Check the error when getting a non-existing object
		err = layer.GetObject(ctx, testBucket, testFile, 0, 0, nil, "", minio.ObjectOptions{})
		assert.Equal(t, minio.ObjectNotFound{Bucket: testBucket, Object: testFile}, err)

		// Create the object using the Uplink API
		metadata := map[string]string{
			"content-type": "text/plain",
			"key1":         "value1",
			"key2":         "value2",
		}
		_, err = createFile(ctx, project, testBucketInfo.Name, testFile, []byte("abcdef"), metadata)
		assert.NoError(t, err)

		for i, tt := range []struct {
			offset, length int64
			substr         string
			err            bool
		}{
			{offset: 0, length: 0, substr: ""},
			{offset: 0, length: -1, substr: "abcdef"},
			{offset: 0, length: 100, substr: "abcdef"},
			{offset: 3, length: 0, substr: ""},
			{offset: 3, length: -1, substr: "def"},
			{offset: 3, length: 100, substr: "def"},
			{offset: 0, length: 6, substr: "abcdef"},
			{offset: 0, length: 5, substr: "abcde"},
			{offset: 0, length: 4, substr: "abcd"},
			{offset: 1, length: 4, substr: "bcde"},
			{offset: 2, length: 4, substr: "cdef"},
			{offset: -1, length: 7, err: true},
			{offset: 0, length: -2, err: true},
		} {
			errTag := fmt.Sprintf("%d. %+v", i, tt)

			var buf bytes.Buffer

			// Get the object info using the Minio API
			err = layer.GetObject(ctx, testBucket, testFile, tt.offset, tt.length, &buf, "", minio.ObjectOptions{})

			if tt.err {
				assert.Error(t, err, errTag)
			} else if assert.NoError(t, err) {
				assert.Equal(t, tt.substr, buf.String(), errTag)
			}
		}
	})
}

func TestCopyObject(t *testing.T) {
	t.Parallel()

	runTest(t, func(t *testing.T, ctx context.Context, layer minio.ObjectLayer, project *uplink.Project) {
		// Check the error when copying an object from a bucket with empty name
		_, err := layer.CopyObject(ctx, "", testFile, destBucket, destFile, minio.ObjectInfo{}, minio.ObjectOptions{}, minio.ObjectOptions{})
		assert.Equal(t, minio.BucketNameInvalid{}, err)

		// Check the error when copying an object from non-existing bucket
		_, err = layer.CopyObject(ctx, testBucket, testFile, destBucket, destFile, minio.ObjectInfo{}, minio.ObjectOptions{}, minio.ObjectOptions{})
		assert.Equal(t, minio.BucketNotFound{Bucket: testBucket}, err)

		// Create the source bucket using the Uplink API
		testBucketInfo, err := project.CreateBucket(ctx, testBucket)
		assert.NoError(t, err)

		// Check the error when copying an object with empty name
		_, err = layer.CopyObject(ctx, testBucket, "", destBucket, destFile, minio.ObjectInfo{}, minio.ObjectOptions{}, minio.ObjectOptions{})
		assert.Equal(t, minio.ObjectNameInvalid{Bucket: testBucket}, err)

		// Create the source object using the Uplink API
		metadata := map[string]string{
			"content-type": "text/plain",
			"key1":         "value1",
			"key2":         "value2",
		}
		obj, err := createFile(ctx, project, testBucketInfo.Name, testFile, []byte("test"), metadata)
		assert.NoError(t, err)

		// Get the source object info using the Minio API
		srcInfo, err := layer.GetObjectInfo(ctx, testBucket, testFile, minio.ObjectOptions{})
		assert.NoError(t, err)

		// Check the error when copying an object to a bucket with empty name
		_, err = layer.CopyObject(ctx, testBucket, testFile, "", destFile, srcInfo, minio.ObjectOptions{}, minio.ObjectOptions{})
		assert.Equal(t, minio.BucketNameInvalid{}, err)

		// Check the error when copying an object to a non-existing bucket
		_, err = layer.CopyObject(ctx, testBucket, testFile, destBucket, destFile, srcInfo, minio.ObjectOptions{}, minio.ObjectOptions{})
		assert.Equal(t, minio.BucketNotFound{Bucket: destBucket}, err)

		// Create the destination bucket using the Uplink API
		destBucketInfo, err := project.CreateBucket(ctx, destBucket)
		assert.NoError(t, err)

		// Copy the object using the Minio API
		info, err := layer.CopyObject(ctx, testBucket, testFile, destBucket, destFile, srcInfo, minio.ObjectOptions{}, minio.ObjectOptions{})
		if assert.NoError(t, err) {
			assert.Equal(t, destFile, info.Name)
			assert.Equal(t, destBucket, info.Bucket)
			assert.False(t, info.IsDir)

			// TODO upload.Info() is using StreamID creation time but this value is different
			// than last segment creation time, CommitObject request should return latest info
			// about object and those values should be used with upload.Info()
			// This should be working after final fix
			// assert.Equal(t, info.ModTime, obj.Info.Created)
			assert.WithinDuration(t, info.ModTime, obj.System.Created, 5*time.Second)

			assert.Equal(t, obj.System.ContentLength, info.Size)
			assert.Equal(t, "text/plain", info.ContentType)
			assert.EqualValues(t, obj.Custom, info.UserDefined)
		}

		// Check that the destination object is uploaded using the Uplink API
		obj, err = project.StatObject(ctx, destBucketInfo.Name, destFile)
		if assert.NoError(t, err) {
			assert.Equal(t, destFile, obj.Key)
			assert.False(t, obj.IsPrefix)

			// TODO upload.Info() is using StreamID creation time but this value is different
			// than last segment creation time, CommitObject request should return latest info
			// about object and those values should be used with upload.Info()
			// This should be working after final fix
			// assert.Equal(t, info.ModTime, obj.Info.Created)
			assert.WithinDuration(t, info.ModTime, obj.System.Created, 2*time.Second)

			assert.Equal(t, info.Size, obj.System.ContentLength)
			assert.Equal(t, info.ContentType, obj.Custom["content-type"])
			assert.EqualValues(t, info.UserDefined, obj.Custom)
		}
	})
}

func TestDeleteObject(t *testing.T) {
	t.Parallel()

	runTest(t, func(t *testing.T, ctx context.Context, layer minio.ObjectLayer, project *uplink.Project) {
		// Check the error when deleting an object from a bucket with empty name
		deleted, err := layer.DeleteObject(ctx, "", "", minio.ObjectOptions{})
		assert.Equal(t, minio.BucketNameInvalid{}, err)
		assert.Empty(t, deleted)

		// Check the error when deleting an object from non-existing bucket
		deleted, err = layer.DeleteObject(ctx, testBucket, testFile, minio.ObjectOptions{})
		assert.Equal(t, minio.BucketNotFound{Bucket: testBucket}, err)
		assert.Empty(t, deleted)

		// Create the bucket using the Uplink API
		testBucketInfo, err := project.CreateBucket(ctx, testBucket)
		assert.NoError(t, err)

		// Check the error when deleting an object with empty name
		deleted, err = layer.DeleteObject(ctx, testBucket, "", minio.ObjectOptions{})
		assert.Equal(t, minio.ObjectNameInvalid{Bucket: testBucket}, err)
		assert.Empty(t, deleted)

		// Check that no error being returned when deleting a non-existing object
		_, err = layer.DeleteObject(ctx, testBucket, testFile, minio.ObjectOptions{})
		require.NoError(t, err)

		// Create the object using the Uplink API
		_, err = createFile(ctx, project, testBucketInfo.Name, testFile, nil, nil)
		assert.NoError(t, err)

		// Delete the object info using the Minio API
		deleted, err = layer.DeleteObject(ctx, testBucket, testFile, minio.ObjectOptions{})
		assert.NoError(t, err)
		assert.Equal(t, testBucket, deleted.Bucket)
		assert.Equal(t, testFile, deleted.Name)

		// Check that the object is deleted using the Uplink API
		_, err = project.StatObject(ctx, testBucketInfo.Name, testFile)
		assert.True(t, errors.Is(err, uplink.ErrObjectNotFound))
	})
}

func TestDeleteObjects(t *testing.T) {
	t.Parallel()

	runTest(t, func(t *testing.T, ctx context.Context, layer minio.ObjectLayer, project *uplink.Project) {
		// Check the error when deleting an object from a bucket with empty name
		deletedObjects, deleteErrors := layer.DeleteObjects(ctx, "", []minio.ObjectToDelete{{ObjectName: testFile}}, minio.ObjectOptions{})
		require.Len(t, deleteErrors, 1)
		assert.Equal(t, minio.BucketNameInvalid{}, deleteErrors[0])
		require.Len(t, deletedObjects, 1)
		assert.Empty(t, deletedObjects[0])

		// Check the error when deleting an object from non-existing bucket
		deletedObjects, deleteErrors = layer.DeleteObjects(ctx, testBucket, []minio.ObjectToDelete{{ObjectName: testFile}}, minio.ObjectOptions{})
		require.Len(t, deleteErrors, 1)
		assert.Equal(t, minio.BucketNotFound{Bucket: testBucket}, deleteErrors[0])
		require.Len(t, deletedObjects, 1)
		assert.Empty(t, deletedObjects[0])

		// Create the bucket using the Uplink API
		testBucketInfo, err := project.CreateBucket(ctx, testBucket)
		assert.NoError(t, err)

		// Check the error when deleting an object with empty name
		deletedObjects, deleteErrors = layer.DeleteObjects(ctx, testBucket, []minio.ObjectToDelete{{ObjectName: ""}}, minio.ObjectOptions{})
		require.Len(t, deleteErrors, 1)
		assert.Equal(t, minio.ObjectNameInvalid{Bucket: testBucket}, deleteErrors[0])
		require.Len(t, deletedObjects, 1)
		assert.Empty(t, deletedObjects[0])

		// Check that there is NO error when deleting a non-existing object
		deletedObjects, deleteErrors = layer.DeleteObjects(ctx, testBucket, []minio.ObjectToDelete{{ObjectName: testFile}}, minio.ObjectOptions{})
		require.Len(t, deleteErrors, 1)
		assert.Empty(t, deleteErrors[0])
		require.Len(t, deletedObjects, 1)
		assert.Equal(t, deletedObjects, []minio.DeletedObject{{ObjectName: testFile}})

		// Create the 3 objects using the Uplink API
		_, err = createFile(ctx, project, testBucketInfo.Name, testFile, nil, nil)
		assert.NoError(t, err)
		_, err = createFile(ctx, project, testBucketInfo.Name, testFile2, nil, nil)
		assert.NoError(t, err)
		_, err = createFile(ctx, project, testBucketInfo.Name, testFile3, nil, nil)
		assert.NoError(t, err)

		// Delete the 1st and the 3rd object using the Minio API
		deletedObjects, deleteErrors = layer.DeleteObjects(ctx, testBucket, []minio.ObjectToDelete{{ObjectName: testFile}, {ObjectName: testFile3}}, minio.ObjectOptions{})
		require.Len(t, deleteErrors, 2)
		assert.NoError(t, deleteErrors[0])
		assert.NoError(t, deleteErrors[1])
		require.Len(t, deletedObjects, 2)
		assert.NotEmpty(t, deletedObjects[0])
		assert.NotEmpty(t, deletedObjects[1])

		// Check using the Uplink API that the 1st and the 3rd objects are deleted, but the 2nd is still there
		_, err = project.StatObject(ctx, testBucketInfo.Name, testFile)
		assert.True(t, errors.Is(err, uplink.ErrObjectNotFound))
		_, err = project.StatObject(ctx, testBucketInfo.Name, testFile2)
		assert.NoError(t, err)
		_, err = project.StatObject(ctx, testBucketInfo.Name, testFile3)
		assert.True(t, errors.Is(err, uplink.ErrObjectNotFound))
	})
}

type listObjectsFunc func(ctx context.Context, layer minio.ObjectLayer, bucket, prefix, marker, delimiter string, maxKeys int) ([]string, []minio.ObjectInfo, string, string, bool, error)

func TestListObjects(t *testing.T) {
	t.Parallel()

	t.Run("once", func(t *testing.T) {
		t.Parallel()

		testListObjects(t, func(ctx context.Context, layer minio.ObjectLayer, bucket, prefix, marker, delimiter string, maxKeys int) ([]string, []minio.ObjectInfo, string, string, bool, error) {
			list, err := layer.ListObjects(ctx, testBucket, prefix, marker, delimiter, maxKeys)
			if err != nil {
				return nil, nil, "", "", false, err
			}
			return list.Prefixes, list.Objects, marker, list.NextMarker, list.IsTruncated, nil
		})
	})
	t.Run("loop", func(t *testing.T) {
		t.Parallel()

		testListObjectsLoop(t, func(ctx context.Context, layer minio.ObjectLayer, bucket, prefix, marker, delimiter string, maxKeys int) ([]string, []minio.ObjectInfo, string, string, bool, error) {
			list, err := layer.ListObjects(ctx, testBucket, prefix, marker, delimiter, maxKeys)
			if err != nil {
				return nil, nil, "", "", false, err
			}
			return list.Prefixes, list.Objects, marker, list.NextMarker, list.IsTruncated, nil
		})
	})
	t.Run("stat", func(t *testing.T) {
		t.Parallel()

		testListObjectsStatLoop(t, func(ctx context.Context, layer minio.ObjectLayer, bucket, prefix, marker, delimiter string, maxKeys int) ([]string, []minio.ObjectInfo, string, string, bool, error) {
			list, err := layer.ListObjects(ctx, testBucket, prefix, marker, delimiter, maxKeys)
			if err != nil {
				return nil, nil, "", "", false, err
			}
			return list.Prefixes, list.Objects, marker, list.NextMarker, list.IsTruncated, nil
		})
	})
}

func TestListObjectsV2(t *testing.T) {
	t.Parallel()

	t.Run("once", func(t *testing.T) {
		t.Parallel()

		testListObjects(t, func(ctx context.Context, layer minio.ObjectLayer, bucket, prefix, marker, delimiter string, maxKeys int) ([]string, []minio.ObjectInfo, string, string, bool, error) {
			list, err := layer.ListObjectsV2(ctx, testBucket, prefix, marker, delimiter, maxKeys, false, "")
			if err != nil {
				return nil, nil, "", "", false, err
			}
			return list.Prefixes, list.Objects, list.ContinuationToken, list.NextContinuationToken, list.IsTruncated, nil
		})
	})
	t.Run("loop", func(t *testing.T) {
		t.Parallel()

		testListObjectsLoop(t, func(ctx context.Context, layer minio.ObjectLayer, bucket, prefix, marker, delimiter string, maxKeys int) ([]string, []minio.ObjectInfo, string, string, bool, error) {
			list, err := layer.ListObjectsV2(ctx, testBucket, prefix, marker, delimiter, maxKeys, false, "")
			if err != nil {
				return nil, nil, "", "", false, err
			}
			return list.Prefixes, list.Objects, list.ContinuationToken, list.NextContinuationToken, list.IsTruncated, nil
		})
	})
	t.Run("stat", func(t *testing.T) {
		t.Parallel()

		testListObjectsStatLoop(t, func(ctx context.Context, layer minio.ObjectLayer, bucket, prefix, marker, delimiter string, maxKeys int) ([]string, []minio.ObjectInfo, string, string, bool, error) {
			list, err := layer.ListObjectsV2(ctx, testBucket, prefix, marker, delimiter, maxKeys, false, "")
			if err != nil {
				return nil, nil, "", "", false, err
			}
			return list.Prefixes, list.Objects, list.ContinuationToken, list.NextContinuationToken, list.IsTruncated, nil
		})
	})
}

func testListObjects(t *testing.T, listObjects listObjectsFunc) {
	runTest(t, func(t *testing.T, ctx context.Context, layer minio.ObjectLayer, project *uplink.Project) {
		// Check the error when listing objects with unsupported delimiter
		_, err := layer.ListObjects(ctx, testBucket, "", "", "#", 0)
		assert.Equal(t, minio.UnsupportedDelimiter{Delimiter: "#"}, err)

		// Check the error when listing objects in a bucket with empty name
		_, err = layer.ListObjects(ctx, "", "", "", "/", 0)
		assert.Equal(t, minio.BucketNameInvalid{}, err)

		// Check the error when listing objects in a non-existing bucket
		_, err = layer.ListObjects(ctx, testBucket, "", "", "", 0)
		assert.Equal(t, minio.BucketNotFound{Bucket: testBucket}, err)

		// Create the bucket and files using the Uplink API
		testBucketInfo, err := project.CreateBucket(ctx, testBucket)
		assert.NoError(t, err)

		filePaths := []string{
			"a", "aa", "b", "bb", "c",
			"a/xa", "a/xaa", "a/xb", "a/xbb", "a/xc",
			"b/ya", "b/yaa", "b/yb", "b/ybb", "b/yc",
			"i", "i/i", "ii", "j", "j/i", "k", "kk", "l",
			"m/i", "mm", "n/i", "oo",
		}

		type expected struct {
			object   *uplink.Object
			metadata map[string]string
		}

		files := make(map[string]expected, len(filePaths))

		metadata := map[string]string{
			"content-type": "text/plain",
			"key1":         "value1",
			"key2":         "value2",
		}
		for _, filePath := range filePaths {
			file, err := createFile(ctx, project, testBucketInfo.Name, filePath, []byte("test"), metadata)
			files[filePath] = expected{
				object:   file,
				metadata: metadata,
			}
			assert.NoError(t, err)
		}

		sort.Strings(filePaths)

		for i, tt := range []struct {
			name      string
			prefix    string
			marker    string
			delimiter string
			maxKeys   int
			more      bool
			prefixes  []string
			objects   []string
		}{
			{
				name:      "Basic non-recursive",
				delimiter: "/",
				prefixes:  []string{"a/", "b/", "i/", "j/", "m/", "n/"},
				objects:   []string{"a", "aa", "b", "bb", "c", "i", "ii", "j", "k", "kk", "l", "mm", "oo"},
			}, {
				name:      "Basic non-recursive with non-existing mark",
				marker:    "`",
				delimiter: "/",
				prefixes:  []string{"a/", "b/", "i/", "j/", "m/", "n/"},
				objects:   []string{"a", "aa", "b", "bb", "c", "i", "ii", "j", "k", "kk", "l", "mm", "oo"},
			}, {
				name:      "Basic non-recursive with existing mark",
				marker:    "b",
				delimiter: "/",
				prefixes:  []string{"b/", "i/", "j/", "m/", "n/"},
				objects:   []string{"bb", "c", "i", "ii", "j", "k", "kk", "l", "mm", "oo"},
			}, {
				name:      "Basic non-recursive with last mark",
				marker:    "oo",
				delimiter: "/",
			}, {
				name:      "Basic non-recursive with past last mark",
				marker:    "ooa",
				delimiter: "/",
			}, {
				name:      "Basic non-recursive with max key limit of 1",
				delimiter: "/",
				maxKeys:   1,
				more:      true,
				objects:   []string{"a"},
			}, {
				name:      "Basic non-recursive with max key limit of 1 with non-existing mark",
				marker:    "`",
				delimiter: "/",
				maxKeys:   1,
				more:      true,
				objects:   []string{"a"},
			}, {
				name:      "Basic non-recursive with max key limit of 1 with existing mark",
				marker:    "aa",
				delimiter: "/",
				maxKeys:   1,
				more:      true,
				objects:   []string{"b"},
			}, {
				name:      "Basic non-recursive with max key limit of 1 with last mark",
				marker:    "oo",
				delimiter: "/",
				maxKeys:   1,
			}, {
				name:      "Basic non-recursive with max key limit of 1 past last mark",
				marker:    "ooa",
				delimiter: "/",
				maxKeys:   1,
			}, {
				name:      "Basic non-recursive with max key limit of 2",
				delimiter: "/",
				maxKeys:   2,
				more:      true,
				prefixes:  []string{"a/"},
				objects:   []string{"a"},
			}, {
				name:      "Basic non-recursive with max key limit of 2 with non-existing mark",
				marker:    "`",
				delimiter: "/",
				maxKeys:   2,
				more:      true,
				prefixes:  []string{"a/"},
				objects:   []string{"a"},
			}, {
				name:      "Basic non-recursive with max key limit of 2 with existing mark",
				marker:    "aa",
				delimiter: "/",
				maxKeys:   2,
				more:      true,
				prefixes:  []string{"b/"},
				objects:   []string{"b"},
			}, {
				name:      "Basic non-recursive with max key limit of 2 with mark right before the end",
				marker:    "nm",
				delimiter: "/",
				maxKeys:   2,
				objects:   []string{"oo"},
			}, {
				name:      "Basic non-recursive with max key limit of 2 with last mark",
				marker:    "oo",
				delimiter: "/",
				maxKeys:   2,
			}, {
				name:      "Basic non-recursive with max key limit of 2 past last mark",
				marker:    "ooa",
				delimiter: "/",
				maxKeys:   2,
			}, {
				name:      "Prefix non-recursive",
				prefix:    "a/",
				delimiter: "/",
				objects:   []string{"xa", "xaa", "xb", "xbb", "xc"},
			}, {
				name:      "Prefix non-recursive with mark",
				prefix:    "a/",
				marker:    "xb",
				delimiter: "/",
				objects:   []string{"xbb", "xc"},
			}, {
				name:      "Prefix non-recursive with mark and max keys",
				prefix:    "a/",
				marker:    "xaa",
				delimiter: "/",
				maxKeys:   2,
				more:      true,
				objects:   []string{"xb", "xbb"},
			}, {
				name:    "Basic recursive",
				objects: filePaths,
			}, {
				name:    "Basic recursive with mark and max keys",
				marker:  "a/xbb",
				maxKeys: 5,
				more:    true,
				objects: []string{"a/xc", "aa", "b", "b/ya", "b/yaa"},
			}, {
				name:     "list as stat, recursive, object, prefix, and object-with-prefix exist",
				prefix:   "i",
				prefixes: nil,
				objects:  []string{"i"},
			}, {
				name:      "list as stat, nonrecursive, object, prefix, and object-with-prefix exist",
				prefix:    "i",
				delimiter: "/",
				prefixes:  []string{"i/"},
				objects:   []string{"i"},
			}, {
				name:     "list as stat, recursive, object and prefix exist, no object-with-prefix",
				prefix:   "j",
				prefixes: nil,
				objects:  []string{"j"},
			}, {
				name:      "list as stat, nonrecursive, object and prefix exist, no object-with-prefix",
				prefix:    "j",
				delimiter: "/",
				prefixes:  []string{"j/"},
				objects:   []string{"j"},
			}, {
				name:     "list as stat, recursive, object and object-with-prefix exist, no prefix",
				prefix:   "k",
				prefixes: nil,
				objects:  []string{"k"},
			}, {
				name:      "list as stat, nonrecursive, object and object-with-prefix exist, no prefix",
				prefix:    "k",
				delimiter: "/",
				prefixes:  nil,
				objects:   []string{"k"},
			}, {
				name:     "list as stat, recursive, object exists, no object-with-prefix or prefix",
				prefix:   "l",
				prefixes: nil,
				objects:  []string{"l"},
			}, {
				name:      "list as stat, nonrecursive, object exists, no object-with-prefix or prefix",
				prefix:    "l",
				delimiter: "/",
				prefixes:  nil,
				objects:   []string{"l"},
			}, {
				name:     "list as stat, recursive, prefix, and object-with-prefix exist, no object",
				prefix:   "m",
				prefixes: nil,
				objects:  nil,
			}, {
				name:      "list as stat, nonrecursive, prefix, and object-with-prefix exist, no object",
				prefix:    "m",
				delimiter: "/",
				prefixes:  []string{"m/"},
				objects:   nil,
			}, {
				name:     "list as stat, recursive, prefix exists, no object-with-prefix, no object",
				prefix:   "n",
				prefixes: nil,
				objects:  nil,
			}, {
				name:      "list as stat, nonrecursive, prefix exists, no object-with-prefix, no object",
				prefix:    "n",
				delimiter: "/",
				prefixes:  []string{"n/"},
				objects:   nil,
			}, {
				name:     "list as stat, recursive, object-with-prefix exists, no prefix, no object",
				prefix:   "o",
				prefixes: nil,
				objects:  nil,
			}, {
				name:      "list as stat, nonrecursive, object-with-prefix exists, no prefix, no object",
				prefix:    "o",
				delimiter: "/",
				prefixes:  nil,
				objects:   nil,
			}, {
				name:     "list as stat, recursive, no object-with-prefix or prefix or object",
				prefix:   "p",
				prefixes: nil,
				objects:  nil,
			}, {
				name:      "list as stat, nonrecursive, no object-with-prefix or prefix or object",
				prefix:    "p",
				delimiter: "/",
				prefixes:  nil,
				objects:   nil,
			},
		} {
			errTag := fmt.Sprintf("%d. %+v", i, tt)

			// Check that the expected objects can be listed using the Minio API
			prefixes, objects, marker, _, isTruncated, err := listObjects(ctx, layer, testBucket, tt.prefix, tt.marker, tt.delimiter, tt.maxKeys)
			if assert.NoError(t, err, errTag) {
				assert.Equal(t, tt.more, isTruncated, errTag)
				assert.Equal(t, tt.marker, marker, errTag)
				assert.Equal(t, tt.prefixes, prefixes, errTag)
				require.Equal(t, len(tt.objects), len(objects), errTag)
				for i, objectInfo := range objects {
					path := objectInfo.Name
					expected, found := files[path]

					if assert.True(t, found) {
						if tt.prefix != "" && strings.HasSuffix(tt.prefix, "/") {
							assert.Equal(t, tt.prefix+tt.objects[i], objectInfo.Name, errTag)
						} else {
							assert.Equal(t, tt.objects[i], objectInfo.Name, errTag)
						}
						assert.Equal(t, testBucket, objectInfo.Bucket, errTag)
						assert.False(t, objectInfo.IsDir, errTag)

						// TODO upload.Info() is using StreamID creation time but this value is different
						// than last segment creation time, CommitObject request should return latest info
						// about object and those values should be used with upload.Info()
						// This should be working after final fix
						// assert.Equal(t, info.ModTime, obj.Info.Created)
						assert.WithinDuration(t, objectInfo.ModTime, expected.object.System.Created, 1*time.Second)

						assert.Equal(t, expected.object.System.ContentLength, objectInfo.Size, errTag)
						// assert.Equal(t, hex.EncodeToString(obj.Checksum), objectInfo.ETag, errTag)
						assert.Equal(t, expected.metadata["content-type"], objectInfo.ContentType, errTag)
						assert.Equal(t, expected.metadata, objectInfo.UserDefined, errTag)
					}
				}
			}
		}
	})
}

func TestListMultipartUploads(t *testing.T) {
	t.Parallel()

	runTest(t, func(t *testing.T, ctx context.Context, layer minio.ObjectLayer, project *uplink.Project) {
		// Check the error when listing an object from a bucket with empty name
		uploads, err := layer.ListMultipartUploads(ctx, "", "", "", "", "", 1)
		assert.Equal(t, minio.BucketNameInvalid{}, err)
		assert.Empty(t, uploads)

		// Check the error when listing objects from non-existing bucket
		uploads, err = layer.ListMultipartUploads(ctx, testBucket, "", "", "", "", 1)
		assert.Equal(t, minio.BucketNotFound{Bucket: testBucket}, err)
		assert.Empty(t, uploads)

		// Create the bucket using the Uplink API
		_, err = project.CreateBucket(ctx, testBucket)
		assert.NoError(t, err)

		userDefined := make(map[string]string)

		userDefined["something"] = "a-value"
		for _, uploadName := range []string{"multipart-upload", "a/prefixed/multipart-upload"} {
			now := time.Now()
			upload, err := layer.NewMultipartUpload(ctx, testBucket, uploadName, minio.ObjectOptions{
				UserDefined: userDefined,
			})
			require.NoError(t, err)
			require.NotEmpty(t, upload)

			uploads, err = layer.ListMultipartUploads(ctx, testBucket, uploadName, "", "", "", 10)
			require.NoError(t, err)
			require.Len(t, uploads.Uploads, 1)

			assert.Equal(t, testBucket, uploads.Uploads[0].Bucket)
			assert.Equal(t, uploadName, uploads.Uploads[0].Object)
			assert.Equal(t, upload, uploads.Uploads[0].UploadID)
			assert.WithinDuration(t, now, uploads.Uploads[0].Initiated, time.Minute)
			// TODO: It seems we don't record the userDefined field when creating the multipart upload
			// assert.EqualValues(t, userDefined, uploads.Uploads[0].UserDefined)
		}
	})
}

func TestNewMultipartUpload(t *testing.T) {
	t.Parallel()

	runTest(t, func(t *testing.T, ctx context.Context, layer minio.ObjectLayer, project *uplink.Project) {
		bucket, err := project.CreateBucket(ctx, testBucket)
		require.NoError(t, err)
		require.Equal(t, bucket.Name, testBucket)

		listParts, err := layer.ListMultipartUploads(ctx, testBucket, "", "", "", "", 1)
		require.NoError(t, err)
		require.Empty(t, listParts.Uploads)

		_, err = layer.NewMultipartUpload(ctx, testBucket, testFile, minio.ObjectOptions{})
		require.NoError(t, err)
		_, err = layer.NewMultipartUpload(ctx, testBucket, testFile2, minio.ObjectOptions{})
		require.NoError(t, err)

		listParts, err = layer.ListMultipartUploads(ctx, testBucket, "", "", "", "", 2)
		require.NoError(t, err)
		require.Len(t, listParts.Uploads, 2)
	})
}

func TestCopyObjectPart(t *testing.T) {
	t.Parallel()

	runTest(t, func(t *testing.T, ctx context.Context, layer minio.ObjectLayer, project *uplink.Project) {
		_, err := layer.CopyObjectPart(ctx, "srcBucket", "srcObject", "destBucket", "destObject", "uploadID", 0, 0, 10, minio.ObjectInfo{}, minio.ObjectOptions{}, minio.ObjectOptions{})
		require.EqualError(t, err, minio.NotImplemented{}.Error())
	})
}

func TestPutObjectStorageClass(t *testing.T) {
	t.Parallel()

	runTest(t, func(t *testing.T, ctx context.Context, layer minio.ObjectLayer, project *uplink.Project) {
		opts := minio.ObjectOptions{
			UserDefined: map[string]string{
				xhttp.AmzStorageClass: "REDUCED_REDUNDANCY",
			},
		}
		_, err := layer.PutObject(ctx, "srcBucket", "srcObject", nil, opts)
		require.EqualError(t, err, minio.NotImplemented{API: "PutObject (storage class)"}.Error())
	})
}

func TestMultipartUploadStorageClass(t *testing.T) {
	t.Parallel()

	runTest(t, func(t *testing.T, ctx context.Context, layer minio.ObjectLayer, project *uplink.Project) {
		opts := minio.ObjectOptions{
			UserDefined: map[string]string{
				xhttp.AmzStorageClass: "REDUCED_REDUNDANCY",
			},
		}
		_, err := layer.NewMultipartUpload(ctx, "srcBucket", "srcObject", opts)
		require.EqualError(t, err, minio.NotImplemented{API: "NewMultipartUpload (storage class)"}.Error())
	})
}

func TestCopyObjectStorageClass(t *testing.T) {
	t.Parallel()

	runTest(t, func(t *testing.T, ctx context.Context, layer minio.ObjectLayer, project *uplink.Project) {
		srcInfo := minio.ObjectInfo{
			UserDefined: map[string]string{
				xhttp.AmzStorageClass: "REDUCED_REDUNDANCY",
			},
		}
		_, err := layer.CopyObject(ctx, "srcBucket", "srcObject", "destBucket", "destObject", srcInfo, minio.ObjectOptions{}, minio.ObjectOptions{})
		require.EqualError(t, err, minio.NotImplemented{API: "CopyObject (storage class)"}.Error())
	})
}

func TestPutObjectPart(t *testing.T) {
	t.Parallel()

	runTest(t, func(t *testing.T, ctx context.Context, layer minio.ObjectLayer, project *uplink.Project) {
		bucket, err := project.CreateBucket(ctx, testBucket)
		require.NoError(t, err)
		require.Equal(t, bucket.Name, testBucket)

		listInfo, err := layer.ListMultipartUploads(ctx, testBucket, "", "", "", "", 1)
		require.NoError(t, err)
		require.Empty(t, listInfo.Uploads)

		uploadID, err := layer.NewMultipartUpload(ctx, testBucket, testFile, minio.ObjectOptions{})
		require.NoError(t, err)

		totalPartsCount := 3
		for i := 1; i <= totalPartsCount; i++ {
			info, err := layer.PutObjectPart(ctx, testBucket, testFile, uploadID, i, newMinioPutObjReader(t), minio.ObjectOptions{})
			require.NoError(t, err)
			require.Equal(t, i, info.PartNumber)
		}

		listParts, err := layer.ListObjectParts(ctx, testBucket, testFile, uploadID, 0, totalPartsCount, minio.ObjectOptions{})
		require.NoError(t, err)
		require.Len(t, listParts.Parts, totalPartsCount)
		require.Equal(t, testBucket, listParts.Bucket)
		require.Equal(t, testFile, listParts.Object)
		require.Equal(t, uploadID, listParts.UploadID)

		require.Equal(t, listParts.Parts[0].PartNumber, 1)
		require.Equal(t, listParts.Parts[1].PartNumber, 2)
		require.Equal(t, listParts.Parts[2].PartNumber, 3)
	})
}

func TestPutObjectPartZeroBytesOnlyPart(t *testing.T) {
	t.Parallel()

	runTest(t, func(t *testing.T, ctx context.Context, layer minio.ObjectLayer, project *uplink.Project) {
		bucket, err := project.CreateBucket(ctx, testBucket)
		require.NoError(t, err)

		uploadID, err := layer.NewMultipartUpload(ctx, bucket.Name, testFile, minio.ObjectOptions{})
		require.NoError(t, err)

		defer func() {
			if err = layer.AbortMultipartUpload(ctx, bucket.Name, testFile, uploadID, minio.ObjectOptions{}); err != nil {
				assert.ErrorIs(t, err, minio.InvalidUploadID{Bucket: bucket.Name, Object: testFile, UploadID: uploadID})
			}
		}()

		h, err := hash.NewReader(
			bytes.NewReader(make([]byte, 0)),
			0,
			"d41d8cd98f00b204e9800998ecf8427e",
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			0,
			true)
		require.NoError(t, err)

		r := minio.NewPutObjReader(h, nil, nil)

		opts := minio.ObjectOptions{
			UserDefined: make(map[string]string),
		}

		part, err := layer.PutObjectPart(ctx, bucket.Name, testFile, uploadID, 1, r, opts)
		require.NoError(t, err)

		assert.Zero(t, part.Size)
		assert.Zero(t, part.ActualSize)

		parts := []minio.CompletePart{
			{
				PartNumber: part.PartNumber,
				ETag:       part.ETag,
			},
		}

		obj, err := layer.CompleteMultipartUpload(ctx, bucket.Name, testFile, uploadID, parts, opts)
		require.NoError(t, err)

		assert.Zero(t, obj.Size)

		downloaded, err := project.DownloadObject(ctx, obj.Bucket, obj.Name, nil)
		require.NoError(t, err)

		_, err = downloaded.Read(make([]byte, 1))
		assert.ErrorIs(t, err, io.EOF)

		assert.Zero(t, downloaded.Info().System.ContentLength)

		require.NoError(t, downloaded.Close())
	})
}

func TestPutObjectPartZeroBytesLastPart(t *testing.T) {
	t.Parallel()

	runTest(t, func(t *testing.T, ctx context.Context, layer minio.ObjectLayer, project *uplink.Project) {
		bucket, err := project.CreateBucket(ctx, testBucket)
		require.NoError(t, err)

		uploadID, err := layer.NewMultipartUpload(ctx, bucket.Name, testFile, minio.ObjectOptions{})
		require.NoError(t, err)

		defer func() {
			if err = layer.AbortMultipartUpload(ctx, bucket.Name, testFile, uploadID, minio.ObjectOptions{}); err != nil {
				assert.ErrorIs(t, err, minio.InvalidUploadID{Bucket: bucket.Name, Object: testFile, UploadID: uploadID})
			}
		}()

		const (
			nonZeroContent          = "test"
			nonZeroContentLen       = int64(4)
			nonZeroContentMD5Hex    = "098f6bcd4621d373cade4e832627b4f6"
			nonZeroContentSHA256Hex = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
		)

		var parts []minio.CompletePart

		// Upload two non-zero parts:
		for i := 0; i < 2; i++ {

			h, err := hash.NewReader(
				bytes.NewReader([]byte(nonZeroContent)),
				nonZeroContentLen,
				nonZeroContentMD5Hex,
				nonZeroContentSHA256Hex,
				nonZeroContentLen,
				true)
			require.NoError(t, err)

			r := minio.NewPutObjReader(h, nil, nil)

			opts := minio.ObjectOptions{
				UserDefined: make(map[string]string),
			}

			part, err := layer.PutObjectPart(ctx, bucket.Name, testFile, uploadID, i+1, r, opts)
			require.NoError(t, err)

			assert.Equal(t, nonZeroContentLen, part.Size)
			assert.Equal(t, nonZeroContentLen, part.ActualSize)

			parts = append(parts, minio.CompletePart{PartNumber: part.PartNumber, ETag: part.ETag})
		}

		// Upload one (last) zero-byte part:

		h, err := hash.NewReader(
			bytes.NewReader(make([]byte, 0)),
			0,
			"d41d8cd98f00b204e9800998ecf8427e",
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			0,
			true)
		require.NoError(t, err)

		r := minio.NewPutObjReader(h, nil, nil)

		opts := minio.ObjectOptions{
			UserDefined: make(map[string]string),
		}

		part, err := layer.PutObjectPart(ctx, bucket.Name, testFile, uploadID, 3, r, opts)
		require.NoError(t, err)

		assert.Zero(t, part.Size)
		assert.Zero(t, part.ActualSize)

		parts = append(parts, minio.CompletePart{PartNumber: part.PartNumber, ETag: part.ETag})

		obj, err := layer.CompleteMultipartUpload(ctx, bucket.Name, testFile, uploadID, parts, opts)
		require.NoError(t, err)

		// The uplink library contains unresolved TODO for returning real
		// objects after committing. TODO(amwolff): enable this check after
		// mentioned TODO is completed.
		//
		// assert.Equal(t, 2*nonZeroContentLen, obj.Size)

		// Verify state:

		downloaded, err := project.DownloadObject(ctx, obj.Bucket, obj.Name, nil)
		require.NoError(t, err)

		defer func() { require.NoError(t, downloaded.Close()) }()

		buf := new(bytes.Buffer)

		_, err = io.Copy(buf, downloaded)
		require.NoError(t, err)

		assert.Equal(t, nonZeroContent+nonZeroContent, buf.String())

		assert.Equal(t, 2*nonZeroContentLen, downloaded.Info().System.ContentLength)
	})
}

func testListObjectsLoop(t *testing.T, listObjects listObjectsFunc) {
	runTest(t, func(t *testing.T, ctx context.Context, layer minio.ObjectLayer, project *uplink.Project) {
		testBucketInfo, err := project.CreateBucket(ctx, testBucket)
		require.NoError(t, err)

		wantObjects := make(map[string]struct{})
		wantObjectsWithPrefix := make(map[string]struct{})

		wantPrefixes := make(map[string]struct{})

		for i := 1; i <= 5; i++ {
			for j := 1; j <= 10; j++ {
				file, err := createFile(ctx, project, testBucketInfo.Name, fmt.Sprintf("1/%d/%d/o", i, j), nil, nil)
				require.NoError(t, err)

				wantObjects[file.Key] = struct{}{}

				if i == 3 {
					wantObjectsWithPrefix[file.Key] = struct{}{}
					wantPrefixes[fmt.Sprintf("1/%d/%d/", i, j)] = struct{}{}
				}
			}
		}

		wantNonRecursiveObjects := make(map[string]struct{})

		for i := 0; i < 10; i++ {
			file, err := createFile(ctx, project, testBucketInfo.Name, fmt.Sprintf("1/3/%d", i), nil, nil)
			require.NoError(t, err)

			wantObjects[file.Key] = struct{}{}
			wantObjectsWithPrefix[file.Key] = struct{}{}
			wantNonRecursiveObjects[file.Key] = struct{}{}
		}

		for _, tt := range [...]struct {
			name         string
			prefix       string
			delimiter    string
			limit        int
			wantPrefixes map[string]struct{}
			wantObjects  map[string]struct{}
		}{
			{
				name:         "recursive + no prefix",
				prefix:       "",
				delimiter:    "",
				limit:        2,
				wantPrefixes: map[string]struct{}{},
				wantObjects:  wantObjects,
			},
			{
				name:         "recursive + with prefix",
				prefix:       "1/3/",
				delimiter:    "",
				limit:        1,
				wantPrefixes: map[string]struct{}{},
				wantObjects:  wantObjectsWithPrefix,
			},
			{
				name:         "non-recursive + no prefix",
				prefix:       "",
				delimiter:    "/",
				limit:        2,
				wantPrefixes: map[string]struct{}{"1/": {}},
				wantObjects:  map[string]struct{}{},
			},
			{
				name:         "non-recursive + with prefix",
				prefix:       "1/3/",
				delimiter:    "/",
				limit:        1,
				wantPrefixes: wantPrefixes,
				wantObjects:  wantNonRecursiveObjects,
			},
		} {
			prefixes, objects, err := listBucketObjects(ctx, listObjects, layer, tt.prefix, tt.delimiter, tt.limit, "")
			require.NoError(t, err, tt.name)
			assert.Equal(t, tt.wantPrefixes, prefixes, tt.name)
			assert.Equal(t, tt.wantObjects, objects, tt.name)
		}
	})
}

func testListObjectsStatLoop(t *testing.T, listObjects listObjectsFunc) {
	runTest(t, func(t *testing.T, ctx context.Context, layer minio.ObjectLayer, project *uplink.Project) {
		testBucketInfo, err := project.CreateBucket(ctx, testBucket)
		require.NoError(t, err)

		for i := 1; i <= 2; i++ {
			for j := 1; j <= 4; j++ {
				_, err = createFile(ctx, project, testBucketInfo.Name, fmt.Sprintf("1/%d/%d", i, j), nil, nil)
				require.NoError(t, err)
				_, err = createFile(ctx, project, testBucketInfo.Name, fmt.Sprintf("1/%d/%d/o", i, j), nil, nil)
				require.NoError(t, err)
			}
		}

		for _, tt := range [...]struct {
			name         string
			prefix       string
			delimiter    string
			limit        int
			startAfter   string
			wantPrefixes bool
			wantObjects  bool
		}{
			{
				name:         "recursive + unlimited",
				prefix:       "1/1/1",
				delimiter:    "",
				limit:        2,
				startAfter:   "",
				wantPrefixes: false,
				wantObjects:  true,
			},
			{
				name:         "recursive + limited",
				prefix:       "1/1/2",
				delimiter:    "",
				limit:        1,
				startAfter:   "",
				wantPrefixes: false,
				wantObjects:  true,
			},
			{
				name:         "non-recursive + unlimited",
				prefix:       "1/1/3",
				delimiter:    "/",
				limit:        0,
				startAfter:   "",
				wantPrefixes: true,
				wantObjects:  true,
			},
			{
				name:         "non-recursive + limited",
				prefix:       "1/1/4",
				delimiter:    "/",
				limit:        1,
				startAfter:   "",
				wantPrefixes: true,
				wantObjects:  true,
			},
			{
				name:         "startAfter implies object is listed after prefix",
				prefix:       "1/2/1",
				delimiter:    "/",
				limit:        2,
				startAfter:   "1/2/1/",
				wantPrefixes: false,
				wantObjects:  false,
			},
			{
				name:         "startAfter is garbage",
				prefix:       "1/2/2",
				delimiter:    "/",
				limit:        1,
				startAfter:   "invalid",
				wantPrefixes: false,
				wantObjects:  false,
			},
			{
				name:         "startAfter replaces continuationToken",
				prefix:       "1/2/3",
				delimiter:    "/",
				limit:        0,
				startAfter:   "1/2/3",
				wantPrefixes: true,
				wantObjects:  false,
			},
		} {
			prefixes, objects, err := listBucketObjects(ctx, listObjects, layer, tt.prefix, tt.delimiter, tt.limit, tt.startAfter)
			require.NoError(t, err, tt.name)

			if tt.wantPrefixes {
				assert.Equal(t, map[string]struct{}{tt.prefix + "/": {}}, prefixes, tt.name)
			} else {
				assert.Empty(t, prefixes, tt.name)
			}

			if tt.wantObjects {
				assert.Equal(t, map[string]struct{}{tt.prefix: {}}, objects, tt.name)
			} else {
				assert.Empty(t, objects, tt.name)
			}
		}
	})
}

func listBucketObjects(ctx context.Context, listObjects listObjectsFunc, layer minio.ObjectLayer, prefix, delimiter string, maxKeys int, startAfter string) (map[string]struct{}, map[string]struct{}, error) {
	gotPrefixes, gotObjects := make(map[string]struct{}), make(map[string]struct{})

	for marker, more := "", true; more; {
		if marker == "" {
			marker = startAfter
		}

		prefixes, objects, _, nextContinuationToken, isTruncated, err := listObjects(ctx, layer, testBucket, prefix, marker, delimiter, maxKeys)
		if err != nil {
			return nil, nil, err
		}

		if maxKeys > 0 && len(prefixes)+len(objects) > maxKeys {
			return nil, nil, errors.New("prefixes + objects exceed maxKeys")
		}

		switch isTruncated {
		case true:
			if nextContinuationToken == "" {
				return nil, nil, errors.New("isTruncated is true but nextContinuationToken is empty")
			}
		case false:
			if nextContinuationToken != "" {
				return nil, nil, errors.New("isTruncated is false but nextContinuationToken is not empty")
			}
		}

		for _, p := range prefixes {
			gotPrefixes[p] = struct{}{}
		}

		for _, o := range objects {
			gotObjects[o.Name] = struct{}{}
		}

		marker, more = nextContinuationToken, isTruncated
	}

	return gotPrefixes, gotObjects, nil
}

func TestGetMultipartInfo(t *testing.T) {
	t.Parallel()

	runTest(t, func(t *testing.T, ctx context.Context, layer minio.ObjectLayer, project *uplink.Project) {
		// Check the error when using an empty bucket name
		multipartInfo, err := layer.GetMultipartInfo(ctx, "", "object", "uploadid", minio.ObjectOptions{})
		require.Error(t, err)
		assert.Equal(t, minio.BucketNameInvalid{}, err)
		assert.Empty(t, multipartInfo)

		multipartInfo, err = layer.GetMultipartInfo(ctx, testBucket, "", "uploadid", minio.ObjectOptions{})
		require.Error(t, err)
		assert.Equal(t, minio.ObjectNameInvalid{}, err)
		assert.Empty(t, multipartInfo)

		multipartInfo, err = layer.GetMultipartInfo(ctx, testBucket, "object", "", minio.ObjectOptions{})
		require.Error(t, err)
		assert.Equal(t, minio.InvalidUploadID{}, err)
		assert.Empty(t, multipartInfo)

		// Check the error when getting MultipartInfo from non-existing bucket
		multipartInfo, err = layer.GetMultipartInfo(ctx, testBucket, "object", "uploadid", minio.ObjectOptions{})
		assert.Equal(t, minio.BucketNotFound{Bucket: testBucket}, err)
		assert.Empty(t, multipartInfo)

		// Create the bucket using the Uplink API
		_, err = project.CreateBucket(ctx, testBucket)
		assert.NoError(t, err)

		now := time.Now()
		// TODO when we can have two multipart uploads for the same object key, make tests for this case
		upload, err := layer.NewMultipartUpload(ctx, testBucket, "multipart-upload", minio.ObjectOptions{})
		require.NoError(t, err)
		require.NotEmpty(t, upload)

		// Check the error when getting MultipartInfo from non-existing object
		multipartInfo, err = layer.GetMultipartInfo(ctx, testBucket, "object", upload, minio.ObjectOptions{})
		assert.Equal(t, minio.ObjectNotFound{Bucket: testBucket, Object: "object"}, err)
		assert.Empty(t, multipartInfo)

		multipartInfo, err = layer.GetMultipartInfo(ctx, testBucket, "multipart-upload", upload, minio.ObjectOptions{})
		require.NoError(t, err)

		require.Equal(t, testBucket, multipartInfo.Bucket)
		require.Equal(t, "multipart-upload", multipartInfo.Object)
		require.Equal(t, upload, multipartInfo.UploadID)
		require.WithinDuration(t, now, multipartInfo.Initiated, time.Minute)
	})
}

func TestListObjectParts(t *testing.T) {
	t.Parallel()

	runTest(t, func(t *testing.T, ctx context.Context, layer minio.ObjectLayer, project *uplink.Project) {
		// Check the error when listing parts from a bucket with empty name
		parts, err := layer.ListObjectParts(ctx, "", "", "", 0, 1, minio.ObjectOptions{})
		assert.Equal(t, minio.BucketNameInvalid{}, err)
		assert.Empty(t, parts)

		// Check the error when listing parts of an object with empty key
		parts, err = layer.ListObjectParts(ctx, testBucket, "", "", 0, 1, minio.ObjectOptions{})
		assert.Equal(t, minio.ObjectNameInvalid{Bucket: testBucket}, err)
		assert.Empty(t, parts)

		// Check the error when listing parts of a multipart upload is empty upload ID
		parts, err = layer.ListObjectParts(ctx, testBucket, testFile, "", 0, 1, minio.ObjectOptions{})
		assert.Equal(t, minio.InvalidUploadID{Bucket: testBucket, Object: testFile}, err)
		assert.Empty(t, parts)

		// TODO: This fails because InvalidUploadID is returned instead of BucketNotFound. Check if this is a bug.
		// Check the error when listing parts from non-existing bucket
		// parts, err = layer.ListObjectParts(ctx, TestBucket, TestFile, "uploadid", 0, 1, minio.ObjectOptions{})
		// assert.Equal(t, minio.BucketNotFound{Bucket: TestBucket}, err)
		// assert.Empty(t, parts)

		bucket, err := project.CreateBucket(ctx, testBucket)
		require.NoError(t, err)
		require.Equal(t, bucket.Name, testBucket)

		listInfo, err := layer.ListMultipartUploads(ctx, testBucket, "", "", "", "", 1)
		require.NoError(t, err)
		require.Empty(t, listInfo.Uploads)

		uploadID, err := layer.NewMultipartUpload(ctx, testBucket, testFile, minio.ObjectOptions{})
		require.NoError(t, err)

		now := time.Now()
		totalPartsCount := 3
		minioReaders := make([]*minio.PutObjReader, 3)
		for i := 0; i < totalPartsCount; i++ {
			minioReaders[i] = newMinioPutObjReader(t)
			info, err := layer.PutObjectPart(ctx, testBucket, testFile, uploadID, i+1, minioReaders[i], minio.ObjectOptions{})
			require.NoError(t, err)
			assert.Equal(t, i+1, info.PartNumber)
			assert.Equal(t, minioReaders[i].Size(), info.Size)
			assert.Equal(t, minioReaders[i].ActualSize(), info.ActualSize)
			assert.Equal(t, minioReaders[i].MD5CurrentHexString(), info.ETag)
		}

		listParts, err := layer.ListObjectParts(ctx, testBucket, testFile, uploadID, 0, totalPartsCount, minio.ObjectOptions{})
		require.NoError(t, err)
		require.Equal(t, testBucket, listParts.Bucket)
		require.Equal(t, testFile, listParts.Object)
		require.Equal(t, uploadID, listParts.UploadID)
		require.Len(t, listParts.Parts, totalPartsCount)
		for i := 0; i < totalPartsCount; i++ {
			assert.Equal(t, i+1, listParts.Parts[i].PartNumber)
			assert.Equal(t, minioReaders[i].Size(), listParts.Parts[i].Size)
			assert.Equal(t, minioReaders[i].ActualSize(), listParts.Parts[i].ActualSize)
			assert.WithinDuration(t, now, listParts.Parts[i].LastModified, 5*time.Second)
			assert.Equal(t, minioReaders[i].MD5CurrentHexString(), listParts.Parts[i].ETag)
		}
	})
}

func TestAbortMultipartUpload(t *testing.T) {
	t.Parallel()

	runTest(t, func(t *testing.T, ctx context.Context, layer minio.ObjectLayer, project *uplink.Project) {
		// invalid upload
		err := layer.AbortMultipartUpload(ctx, testBucket, testFile, "uploadID", minio.ObjectOptions{})
		require.Error(t, err)

		bucket, err := project.CreateBucket(ctx, testBucket)
		require.NoError(t, err)
		require.Equal(t, bucket.Name, testBucket)

		uploadID, err := layer.NewMultipartUpload(ctx, testBucket, testFile, minio.ObjectOptions{})
		require.NoError(t, err)

		err = layer.AbortMultipartUpload(ctx, testBucket, testFile, uploadID, minio.ObjectOptions{})
		require.NoError(t, err)
	})
}

func TestCompleteMultipartUpload(t *testing.T) {
	t.Parallel()

	runTest(t, func(t *testing.T, ctx context.Context, layer minio.ObjectLayer, project *uplink.Project) {
		_, err := layer.CompleteMultipartUpload(ctx, "bucket", "object", "invalid-upload", nil, minio.ObjectOptions{})
		require.Error(t, err)

		bucket, err := project.CreateBucket(ctx, testBucket)
		require.NoError(t, err)
		require.Equal(t, bucket.Name, testBucket)

		listInfo, err := layer.ListMultipartUploads(ctx, testBucket, "", "", "", "", 1)
		require.NoError(t, err)
		require.Empty(t, listInfo.Uploads)

		uploadID, err := layer.NewMultipartUpload(ctx, testBucket, testFile, minio.ObjectOptions{})
		require.NoError(t, err)

		totalPartsCount := 3
		completeParts := make([]minio.CompletePart, 0, totalPartsCount)
		for i := 1; i <= totalPartsCount; i++ {
			info, err := layer.PutObjectPart(ctx, testBucket, testFile, uploadID, i, newMinioPutObjReader(t), minio.ObjectOptions{})
			require.NoError(t, err)
			require.Equal(t, i, info.PartNumber)
			completeParts = append(completeParts, minio.CompletePart{
				ETag:       info.ETag,
				PartNumber: i,
			})
		}

		metadata := map[string]string{
			"content-type":         "text/plain",
			xhttp.AmzObjectTagging: "key1=value1&key2=value2",
		}

		expectedMetadata := map[string]string{
			"content-type": "text/plain",
			"s3:tags":      "key1=value1&key2=value2",
		}

		_, err = layer.CompleteMultipartUpload(ctx, testBucket, testFile, uploadID, completeParts, minio.ObjectOptions{UserDefined: metadata})
		require.NoError(t, err)

		obj, err := layer.ListObjects(ctx, testBucket, testFile, "", "", 2)
		require.NoError(t, err)
		require.Len(t, obj.Objects, 1)
		require.Equal(t, testBucket, obj.Objects[0].Bucket)
		require.Equal(t, testFile, obj.Objects[0].Name)

		expectedMetadata["s3:etag"] = obj.Objects[0].ETag

		require.Equal(t, expectedMetadata, obj.Objects[0].UserDefined)
	})
}

func TestDeleteObjectWithNoReadOrListPermission(t *testing.T) {
	t.Parallel()

	runTest(t, func(t *testing.T, ctx context.Context, layer minio.ObjectLayer, project *uplink.Project) {
		// Create the bucket using the Uplink API
		testBucketInfo, err := project.CreateBucket(ctx, testBucket)
		require.NoError(t, err)

		// Create the object using the Uplink API
		_, err = createFile(ctx, project, testBucketInfo.Name, testFile, nil, nil)
		require.NoError(t, err)

		access, err := uplink.ParseAccess(logger.GetReqInfo(ctx).AccessGrant)
		require.NoError(t, err)

		// Restrict the access grant to deletes only
		restrictedAccess, err := access.Share(uplink.Permission{AllowDelete: true})
		require.NoError(t, err)

		restrictedAccessString, err := restrictedAccess.Serialize()
		require.NoError(t, err)

		// Set the restricted Access Grant as the S3 Access Key in the Context
		ctx = logger.SetReqInfo(ctx, &logger.ReqInfo{AccessGrant: restrictedAccessString})

		// Delete the object info using the Minio API
		deleted, err := layer.DeleteObject(ctx, testBucket, testFile, minio.ObjectOptions{})
		require.NoError(t, err)
		require.Equal(t, testBucket, deleted.Bucket)
		require.Empty(t, deleted.Name)

		// Check that the object is deleted using the Uplink API
		_, err = project.StatObject(ctx, testBucketInfo.Name, testFile)
		require.True(t, errors.Is(err, uplink.ErrObjectNotFound))
	})
}

func TestListObjectVersions(t *testing.T) {
	t.Parallel()

	runTest(t, func(t *testing.T, ctx context.Context, layer minio.ObjectLayer, project *uplink.Project) {
		_, err := layer.ListObjectVersions(ctx, "bucket", "prefix", "marker", "versionMarker", "delimiter", 0)
		require.EqualError(t, err, minio.NotImplemented{}.Error())
	})
}

func TestPutObjectTags(t *testing.T) {
	t.Parallel()

	runTest(t, func(t *testing.T, ctx context.Context, layer minio.ObjectLayer, project *uplink.Project) {
		// Check the error when putting object tags from a bucket with empty name
		err := layer.PutObjectTags(ctx, "", "", "key1=value1", minio.ObjectOptions{})
		assert.Equal(t, minio.BucketNameInvalid{}, err)

		// Check the error when putting object tags with a non-existent bucket
		err = layer.PutObjectTags(ctx, testBucket, testFile, "key1=value1", minio.ObjectOptions{})
		assert.Equal(t, minio.BucketNotFound{Bucket: testBucket}, err)

		// Create the bucket using the Uplink API
		testBucketInfo, err := project.CreateBucket(ctx, testBucket)
		require.NoError(t, err)

		// Check the error when putting object tags for an object with empty name
		err = layer.PutObjectTags(ctx, testBucket, "", "key1=value1", minio.ObjectOptions{})
		assert.Equal(t, minio.ObjectNameInvalid{Bucket: testBucket}, err)

		// Check the error when putting object tags with a non-existing object
		err = layer.PutObjectTags(ctx, testBucket, testFile, "key1=value1", minio.ObjectOptions{})
		assert.Equal(t, minio.ObjectNotFound{Bucket: testBucket, Object: testFile}, err)

		// These are the object tags we want to put
		objectTags := "key3=value3&key4=value4"

		// This is the tag map expected from GetObjectTags
		expectedObjectTags := map[string]string{
			"key3": "value3",
			"key4": "value4",
		}

		// Create the object using the Uplink API
		_, err = createFile(ctx, project, testBucketInfo.Name, testFile, []byte("test"), nil)
		require.NoError(t, err)

		err = layer.PutObjectTags(ctx, testBucket, testFile, objectTags, minio.ObjectOptions{})
		require.NoError(t, err)

		ts, err := layer.GetObjectTags(ctx, testBucket, testFile, minio.ObjectOptions{})
		require.NoError(t, err)
		assert.Equal(t, expectedObjectTags, ts.ToMap())

		// Test that sending an empty tag set is effectively the same as deleting them
		err = layer.PutObjectTags(ctx, testBucket, testFile, "", minio.ObjectOptions{})
		require.NoError(t, err)

		ts, err = layer.GetObjectTags(ctx, testBucket, testFile, minio.ObjectOptions{})
		require.NoError(t, err)
		assert.Empty(t, ts.ToMap())
	})
}

func TestGetObjectTags(t *testing.T) {
	t.Parallel()

	runTest(t, func(t *testing.T, ctx context.Context, layer minio.ObjectLayer, project *uplink.Project) {
		// Check the error when getting object tags from a bucket with empty name
		_, err := layer.GetObjectTags(ctx, "", "", minio.ObjectOptions{})
		assert.Equal(t, minio.BucketNameInvalid{}, err)

		// Check the error when getting object tags with a non-existent bucket
		_, err = layer.GetObjectTags(ctx, testBucket, testFile, minio.ObjectOptions{})
		assert.Equal(t, minio.BucketNotFound{Bucket: testBucket}, err)

		// Create the bucket using the Uplink API
		testBucketInfo, err := project.CreateBucket(ctx, testBucket)
		require.NoError(t, err)

		// Check the error when getting object tags for an object with empty name
		_, err = layer.GetObjectTags(ctx, testBucket, "", minio.ObjectOptions{})
		assert.Equal(t, minio.ObjectNameInvalid{Bucket: testBucket}, err)

		// Check the error when getting object tags with a non-existent object
		_, err = layer.GetObjectTags(ctx, testBucket, testFile, minio.ObjectOptions{})
		assert.Equal(t, minio.ObjectNotFound{Bucket: testBucket, Object: testFile}, err)

		// This is the custom metadata for the object.
		metadata := map[string]string{
			"content-type": "text/plain",
			"s3:tags":      "key1=value1&key2=value2",
		}

		// These are the expected object tags from that metadata.
		expected := map[string]string{
			"key1": "value1",
			"key2": "value2",
		}

		// Create the object using the Uplink API
		_, err = createFile(ctx, project, testBucketInfo.Name, testFile, []byte("test"), metadata)
		require.NoError(t, err)

		ts, err := layer.GetObjectTags(ctx, testBucket, testFile, minio.ObjectOptions{})
		require.NoError(t, err)
		assert.Equal(t, expected, ts.ToMap())

		metadataNoObjectTags := map[string]string{
			"content-type": "text/plain",
		}

		_, err = createFile(ctx, project, testBucketInfo.Name, testFile, []byte("test"), metadataNoObjectTags)
		require.NoError(t, err)

		ts, err = layer.GetObjectTags(ctx, testBucket, testFile, minio.ObjectOptions{})
		require.NoError(t, err)
		assert.Empty(t, ts.ToMap())

		metadataEmptyObjectTags := map[string]string{
			"content-type": "text/plain",
			"s3:tags":      "",
		}

		_, err = createFile(ctx, project, testBucketInfo.Name, testFile, []byte("test"), metadataEmptyObjectTags)
		require.NoError(t, err)

		ts, err = layer.GetObjectTags(ctx, testBucket, testFile, minio.ObjectOptions{})
		require.NoError(t, err)
		assert.Empty(t, ts.ToMap())
	})
}

func TestDeleteObjectTags(t *testing.T) {
	t.Parallel()

	runTest(t, func(t *testing.T, ctx context.Context, layer minio.ObjectLayer, project *uplink.Project) {
		// Check the error when deleting object tags from a bucket with empty name
		err := layer.DeleteObjectTags(ctx, "", "", minio.ObjectOptions{})
		assert.Equal(t, minio.BucketNameInvalid{}, err)

		// Check the error when deleting object tags with a non-existent bucket
		err = layer.DeleteObjectTags(ctx, testBucket, testFile, minio.ObjectOptions{})
		assert.Equal(t, minio.BucketNotFound{Bucket: testBucket}, err)

		// Create the bucket using the Uplink API
		testBucketInfo, err := project.CreateBucket(ctx, testBucket)
		require.NoError(t, err)

		// Check the error when deleting object tags for an object with empty name
		err = layer.DeleteObjectTags(ctx, testBucket, "", minio.ObjectOptions{})
		assert.Equal(t, minio.ObjectNameInvalid{Bucket: testBucket}, err)

		// Check the error when deleting object tags for a non-existing object
		err = layer.DeleteObjectTags(ctx, testBucket, testFile, minio.ObjectOptions{})
		assert.Equal(t, minio.ObjectNotFound{Bucket: testBucket, Object: testFile}, err)

		metadata := map[string]string{
			"s3:tags": "key5=value5&key6=value6",
		}

		// Create the object using the Uplink API
		_, err = createFile(ctx, project, testBucketInfo.Name, testFile, []byte("test"), metadata)
		require.NoError(t, err)

		err = layer.DeleteObjectTags(ctx, testBucket, testFile, minio.ObjectOptions{})
		require.NoError(t, err)

		ts, err := layer.GetObjectTags(ctx, testBucket, testFile, minio.ObjectOptions{})
		require.NoError(t, err)
		assert.Empty(t, ts.ToMap())
	})
}

// md5Hex returns MD5 hash in hex encoding of given data.
func md5Hex(data []byte) string {
	sum := md5.Sum(data)
	return hex.EncodeToString(sum[:])
}

// sha256Hex returns SHA-256 hash in hex encoding of given data.
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestProjectUsageLimit(t *testing.T) {
	t.Parallel()

	testplanet.Run(t, testplanet.Config{
		SatelliteCount: 1, StorageNodeCount: 4, UplinkCount: 1,
	}, func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet) {
		satDB := planet.Satellites[0].DB
		acctDB := satDB.ProjectAccounting()

		now := time.Now()
		project := planet.Uplinks[0].Projects[0]

		// set custom bandwidth limit for project 512 Kb
		bandwidthLimit := 500 * memory.KiB
		err := acctDB.UpdateProjectBandwidthLimit(ctx, project.ID, bandwidthLimit)
		require.NoError(t, err)

		dataSize := 100 * memory.KiB
		data := testrand.Bytes(dataSize)

		s3Compatibility := server.S3CompatibilityConfig{
			IncludeCustomMetadataListing: true,
			MaxKeysLimit:                 1000,
		}

		layer, err := server.NewGateway(uplink.Config{}, rpc.NewDefaultConnectionPool(), s3Compatibility, true)
		require.NoError(t, err)

		access, err := setupAccess(ctx, t, planet, storj.EncNull, uplink.FullPermission())
		require.NoError(t, err)

		accessString, err := access.Serialize()
		require.NoError(t, err)

		// Establish new context with the Access Grant for the gateway to pick up.
		ctxWithAccessGrant := logger.SetReqInfo(ctx.Context, &logger.ReqInfo{AccessGrant: accessString})

		// Create a bucket with the Minio API
		err = layer.MakeBucketWithLocation(ctxWithAccessGrant, "testbucket", minio.BucketOptions{})
		assert.NoError(t, err)

		hashReader, err := hash.NewReader(bytes.NewReader(data), int64(dataSize), md5Hex(data), sha256Hex(data), int64(dataSize), true)
		require.NoError(t, err)
		putObjectReader := minio.NewPutObjReader(hashReader, nil, nil)

		info, err := layer.PutObject(ctxWithAccessGrant, "testbucket", "test/path1", putObjectReader, minio.ObjectOptions{UserDefined: make(map[string]string)})
		require.NoError(t, err)
		assert.Equal(t, "test/path1", info.Name)
		assert.Equal(t, "testbucket", info.Bucket)
		assert.False(t, info.IsDir)
		assert.True(t, time.Since(info.ModTime) < 1*time.Minute)
		assert.NotEmpty(t, info.ETag)

		time.Sleep(10 * time.Second)
		// We'll be able to download 5X before reach the limit.
		for i := 0; i < 5; i++ {
			err = layer.GetObject(ctxWithAccessGrant, "testbucket", "test/path1", 0, -1, ioutil.Discard, "", minio.ObjectOptions{})
			require.NoError(t, err)
		}

		// An extra download should return 'Exceeded Usage Limit' error
		err = layer.GetObject(ctxWithAccessGrant, "testbucket", "test/path1", 0, -1, ioutil.Discard, "", minio.ObjectOptions{})
		require.Error(t, err)
		require.EqualError(t, err, minio.ProjectUsageLimit{}.Error())

		// Simulate new billing cycle (next month)
		planet.Satellites[0].API.Accounting.ProjectUsage.SetNow(func() time.Time {
			return time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC)
		})

		// Should not return an error since it's a new month
		err = layer.GetObject(ctxWithAccessGrant, "testbucket", "test/path1", 0, -1, ioutil.Discard, "", minio.ObjectOptions{})
		require.NoError(t, err)
	})
}

func runTest(t *testing.T, test func(*testing.T, context.Context, minio.ObjectLayer, *uplink.Project)) {
	runTestWithPathCipher(t, storj.EncNull, test)
}

func runTestWithPathCipher(t *testing.T, pathCipher storj.CipherSuite, test func(*testing.T, context.Context, minio.ObjectLayer, *uplink.Project)) {
	testplanet.Run(t, testplanet.Config{
		SatelliteCount: 1, StorageNodeCount: 4, UplinkCount: 1,
	}, func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet) {
		s3Compatibility := server.S3CompatibilityConfig{
			IncludeCustomMetadataListing: true,
			MaxKeysLimit:                 1000,
		}

		layer, err := server.NewGateway(uplink.Config{}, rpc.NewDefaultConnectionPool(), s3Compatibility, true)
		require.NoError(t, err)

		defer func() { require.NoError(t, layer.Shutdown(ctx)) }()

		access, err := setupAccess(ctx, t, planet, pathCipher, uplink.FullPermission())
		require.NoError(t, err)

		accessString, err := access.Serialize()
		require.NoError(t, err)

		project, err := uplink.OpenProject(ctx, access)
		require.NoError(t, err)

		defer func() { require.NoError(t, project.Close()) }()

		// Establish new context with the Access Grant for the gateway to pick up.
		ctxWithAccessGrant := logger.SetReqInfo(ctx.Context, &logger.ReqInfo{AccessGrant: accessString})

		test(t, ctxWithAccessGrant, layer, project)
	})
}

func setupAccess(ctx context.Context, t *testing.T, planet *testplanet.Planet, pathCipher storj.CipherSuite, permission uplink.Permission) (*uplink.Access, error) {
	access := planet.Uplinks[0].Access[planet.Satellites[0].ID()]

	access, err := access.Share(permission)
	if err != nil {
		return nil, err
	}

	serializedAccess, err := access.Serialize()
	if err != nil {
		return nil, err
	}

	data, version, err := base58.CheckDecode(serializedAccess)
	if err != nil || version != 0 {
		return nil, errors.New("invalid access grant format")
	}

	p := new(pb.Scope)

	if err := pb.Unmarshal(data, p); err != nil {
		return nil, err

	}

	p.EncryptionAccess.DefaultPathCipher = pb.CipherSuite(pathCipher)

	accessData, err := pb.Marshal(p)
	if err != nil {
		return nil, err
	}

	serializedAccess = base58.CheckEncode(accessData, 0)

	// workaround to set proper path cipher for uplink.Access
	return uplink.ParseAccess(serializedAccess)
}

func createFile(ctx context.Context, project *uplink.Project, bucket, key string, data []byte, metadata map[string]string) (*uplink.Object, error) {
	upload, err := project.UploadObject(ctx, bucket, key, nil)
	if err != nil {
		return nil, err
	}

	_, err = io.Copy(upload, bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}

	err = upload.SetCustomMetadata(ctx, metadata)
	if err != nil {
		return nil, err
	}

	err = upload.Commit()
	if err != nil {
		return nil, err
	}

	return upload.Info(), nil
}

func newMinioPutObjReader(t *testing.T) *minio.PutObjReader {
	hashReader, err := hash.NewReader(bytes.NewReader([]byte("test")),
		int64(len("test")),
		"098f6bcd4621d373cade4e832627b4f6",
		"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		int64(len("test")),
		true,
	)
	require.NoError(t, err)

	return minio.NewPutObjReader(hashReader, nil, nil)
}
