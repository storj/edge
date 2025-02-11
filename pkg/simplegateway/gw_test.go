// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package simplegateway

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"storj.io/common/testcontext"
	minio "storj.io/minio/cmd"
	"storj.io/minio/pkg/hash"
)

func TestMakeBucketWithLocation(t *testing.T) {
	ctx := testcontext.New(t)

	dataDir := t.TempDir()
	layer := &gatewayLayer{dataDir: dataDir}

	require.NoError(t, layer.MakeBucketWithLocation(ctx, "testbucket", minio.BucketOptions{}))

	_, err := os.Stat(filepath.Join(dataDir, "testbucket"))
	require.NoError(t, err)
}

func TestBucketInfo(t *testing.T) {
	ctx := testcontext.New(t)

	dataDir := t.TempDir()
	layer := &gatewayLayer{dataDir: dataDir}

	require.NoError(t, layer.MakeBucketWithLocation(ctx, "testbucket", minio.BucketOptions{}))

	info, err := layer.GetBucketInfo(ctx, "testbucket")
	require.NoError(t, err)
	require.Equal(t, "testbucket", info.Name)
}

func TestGetObjectInfo(t *testing.T) {
	ctx := testcontext.New(t)

	dataDir := t.TempDir()
	layer := &gatewayLayer{dataDir: dataDir}

	require.NoError(t, layer.MakeBucketWithLocation(ctx, "testbucket", minio.BucketOptions{}))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "testbucket", "testobject"), []byte("testdata"), 0644))

	info, err := layer.GetObjectInfo(ctx, "testbucket", "testobject", minio.ObjectOptions{})
	require.NoError(t, err)
	require.Equal(t, "testobject", info.Name)
	require.Equal(t, int64(8), info.Size)
}

func TestGetObjectNInfo(t *testing.T) {
	ctx := testcontext.New(t)

	dataDir := t.TempDir()
	layer := &gatewayLayer{dataDir: dataDir}

	require.NoError(t, layer.MakeBucketWithLocation(ctx, "testbucket", minio.BucketOptions{}))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "testbucket", "testobject"), []byte("testdata"), 0644))

	// ranged reads aren't supported, the full content is always returned.
	reader, err := layer.GetObjectNInfo(ctx, "testbucket", "testobject", &minio.HTTPRangeSpec{Start: 3, End: 7}, nil, 0, minio.ObjectOptions{})
	require.NoError(t, err)
	defer func() {
		_ = reader.Close()
	}()

	data, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Equal(t, "testdata", string(data))
}

func TestPutObject(t *testing.T) {
	ctx := testcontext.New(t)

	dataDir := t.TempDir()
	layer := &gatewayLayer{dataDir: dataDir}

	require.NoError(t, layer.MakeBucketWithLocation(ctx, "testbucket", minio.BucketOptions{}))

	hashReader, err := hash.NewReader(bytes.NewReader([]byte("test")),
		int64(len("test")),
		"098f6bcd4621d373cade4e832627b4f6",
		"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		int64(len("test")),
	)
	require.NoError(t, err)

	data := minio.NewPutObjReader(hashReader)

	_, err = layer.PutObject(ctx, "testbucket", "testobject", data, minio.ObjectOptions{})
	require.NoError(t, err)

	_, err = os.Stat(filepath.Join(dataDir, "testbucket", "testobject"))
	require.NoError(t, err)

	_, err = layer.PutObject(ctx, "newbucket", "testobject/something/else", data, minio.ObjectOptions{})
	require.NoError(t, err)

	_, err = os.Stat(filepath.Join(dataDir, "newbucket", "testobject/something/else"))
	require.NoError(t, err)
}

func TestResolvePath(t *testing.T) {
	for _, tt := range []struct {
		root, path, expectedPath string
		valid                    bool
	}{
		{"", "/some/absolute/path", "", false},
		{"/mnt/data", "/some/absolute/path", "", false},
		{"/mnt/data", "../../etc/hosts", "", false},
		{"/mnt/data/", "../../etc/hosts", "", false},
		{"/mnt/data", "file/../etc/hosts", "/mnt/data/etc/hosts", true},
		{"/mnt/data", "testpath", "/mnt/data/testpath", true},
		{"/mnt/data/", "testbucket/testpath", "/mnt/data/testbucket/testpath", true},
		{"/mnt/data", "testbucket/something", "/mnt/data/testbucket/something", true},
		{"/mnt/data", "testbucket/../something", "/mnt/data/something", true},
		{"/mnt/data", "testbucket/../../something", "", false},
		{"/mnt/data", "~/myfiles", "/mnt/data/~/myfiles", true},
	} {
		t.Run(filepath.Join(tt.root, tt.path), func(t *testing.T) {
			path, err := resolvePath(tt.root, tt.path)
			if tt.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				return
			}
			require.Equal(t, tt.expectedPath, path)
		})
	}
}
