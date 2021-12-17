// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"storj.io/common/memory"
	"storj.io/common/testcontext"
	"storj.io/gateway-mt/pkg/linksharing/objectmap"
	"storj.io/uplink"
)

func TestDownloadContentTypeHeader(t *testing.T) {
	cfg := Config{
		URLBases:  []string{"http://test.test"},
		Templates: "../../../pkg/linksharing/web/",
	}

	handler, err := NewHandler(&zap.Logger{}, &objectmap.IPDB{}, cfg)
	require.NoError(t, err)

	ctx := testcontext.New(t)
	w := httptest.NewRecorder()

	r, err := http.NewRequestWithContext(ctx, "GET", "http://test.test?download", nil)
	require.NoError(t, err)

	pr := &parsedRequest{}
	project := &uplink.Project{}
	object := &uplink.Object{
		Key: "test.jpg",
	}

	err = handler.showObject(ctx, w, r, pr, project, object)
	require.NoError(t, err)

	ctypes, haveType := w.Header()["Content-Type"]
	require.True(t, haveType)
	require.Equal(t, "image/jpeg", ctypes[0])

	object.Key = "test"

	err = handler.showObject(ctx, w, r, pr, project, object)
	require.NoError(t, err)

	ctypes, haveType = w.Header()["Content-Type"]
	require.True(t, haveType)
	require.Equal(t, "application/octet-stream", ctypes[0])

	object.Custom = uplink.CustomMetadata{
		"Content-Type": "image/somethingelse",
	}

	err = handler.showObject(ctx, w, r, pr, project, object)
	require.NoError(t, err)

	ctypes, haveType = w.Header()["Content-Type"]
	require.True(t, haveType)
	require.Equal(t, "image/somethingelse", ctypes[0])
}

func TestImagePreviewPath(t *testing.T) {
	for i, tt := range [...]struct {
		access string
		bucket string
		key    string
		size   int64

		wantTwitterImage string
		wantOgImage      string
	}{
		{
			access:           "",
			bucket:           "bucket",
			key:              "key.jpg",
			size:             100 * memory.KB.Int64(),
			wantTwitterImage: "/raw/bucket/key.jpg",
			wantOgImage:      "/raw/bucket/key.jpg",
		},
		{
			access:           "access",
			bucket:           "bucket",
			key:              "key.jpeg",
			size:             100 * memory.KB.Int64(),
			wantTwitterImage: "/raw/access/bucket/key.jpeg",
			wantOgImage:      "/raw/access/bucket/key.jpeg",
		},

		{
			access:           "access",
			bucket:           "bucket",
			key:              "key.webp",
			size:             100 * memory.KB.Int64(),
			wantTwitterImage: "/raw/access/bucket/key.webp",
			wantOgImage:      "",
		},
		{
			access:           "access",
			bucket:           "bucket",
			key:              "key.jpg",
			size:             4 * memory.MB.Int64(),
			wantTwitterImage: "",
			wantOgImage:      "/raw/access/bucket/key.jpg",
		},

		{
			access:           "access",
			bucket:           "bucket",
			key:              "key.webp",
			size:             5 * memory.MB.Int64(),
			wantTwitterImage: "",
			wantOgImage:      "",
		},
		{
			access:           "access",
			bucket:           "bucket",
			key:              "key.rar",
			size:             6 * memory.KB.Int64(),
			wantTwitterImage: "",
			wantOgImage:      "",
		},
		{
			access:           "access",
			bucket:           "bucket",
			key:              "key.jpeg",
			size:             7 * memory.MB.Int64(),
			wantTwitterImage: "",
			wantOgImage:      "",
		},
	} {
		twitterImage, ogImage := imagePreviewPath(tt.access, tt.bucket, tt.key, tt.size)
		assert.Equal(t, tt.wantTwitterImage, twitterImage, i)
		assert.Equal(t, tt.wantOgImage, ogImage, i)
	}
}
