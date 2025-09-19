// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"storj.io/common/memory"
	"storj.io/common/ranger"
	"storj.io/common/ranger/httpranger"
	"storj.io/common/testcontext"
	"storj.io/edge/pkg/errdata"
	"storj.io/edge/pkg/linksharing/objectmap"
	"storj.io/uplink"
)

func TestDownloadMetadataHeaders(t *testing.T) {
	testCases := []struct {
		desc                       string
		cacheControlMetadataKey    string
		contentTypeMetadataKey     string
		contentEncodingMetadataKey string
	}{
		{
			desc:                       "lowercase",
			cacheControlMetadataKey:    "cache-control",
			contentTypeMetadataKey:     "content-type",
			contentEncodingMetadataKey: "content-encoding",
		},
		{
			desc:                       "capitalized",
			cacheControlMetadataKey:    "Cache-Control",
			contentTypeMetadataKey:     "Content-Type",
			contentEncodingMetadataKey: "Content-Encoding",
		},
		{
			desc:                       "mixed case",
			cacheControlMetadataKey:    "Cache-control",
			contentTypeMetadataKey:     "Content-type",
			contentEncodingMetadataKey: "Content-encoding",
		},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			cfg := Config{
				ListPageLimit: 1,
				URLBases:      []string{"http://test.test"},
			}

			handler, err := NewHandler(&zap.Logger{}, &objectmap.IPDB{}, nil, nil, cfg)
			require.NoError(t, err)

			ctx := testcontext.New(t)
			w := httptest.NewRecorder()
			r, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://test.test?download", nil)
			require.NoError(t, err)

			pr := &parsedRequest{}
			project := &uplink.Project{}
			object := &uplink.Object{
				Key: "test.jpg",
			}
			err = handler.showObject(ctx, w, r, pr, project, object, nil, httpranger.HTTPRange{})
			require.NoError(t, err)

			ctypes, haveType := w.Header()["Content-Type"]
			require.True(t, haveType)
			require.Equal(t, "image/jpeg", ctypes[0])

			require.Equal(t, "", w.Header().Get("Cache-Control"))

			object.Key = "test"
			object.Custom = uplink.CustomMetadata{
				tc.cacheControlMetadataKey:    "max-age=0, must-revalidate",
				tc.contentEncodingMetadataKey: "gzip",
			}
			err = handler.showObject(ctx, w, r, pr, project, object, nil, httpranger.HTTPRange{})
			require.NoError(t, err)

			ctypes, haveType = w.Header()["Content-Type"]
			require.True(t, haveType)
			require.Equal(t, "application/octet-stream", ctypes[0])

			require.Equal(t, "max-age=0, must-revalidate", w.Header().Get("Cache-Control"))
			require.Equal(t, "gzip", w.Header().Get("Content-Encoding"))

			object.Custom = uplink.CustomMetadata{
				tc.contentTypeMetadataKey: "image/somethingelse",
			}
			err = handler.showObject(ctx, w, r, pr, project, object, nil, httpranger.HTTPRange{})
			require.NoError(t, err)

			ctypes, haveType = w.Header()["Content-Type"]
			require.True(t, haveType)
			require.Equal(t, "image/somethingelse", ctypes[0])

			object.Custom = uplink.CustomMetadata{
				tc.contentTypeMetadataKey: "text/html",
			}
			err = handler.showObject(ctx, w, r, pr, project, object, nil, httpranger.HTTPRange{})
			require.NoError(t, err)

			ctypes, haveType = w.Header()["Content-Type"]
			require.True(t, haveType)
			require.Equal(t, "text/plain", ctypes[0]) // html isn't allowed for security reasons
		})
	}
}

func TestContentDisposition(t *testing.T) {
	testCases := []struct {
		desc                   string
		contentType            string
		hosting                bool
		standardRendersContent bool
		key                    string
		disposition            []string
	}{
		{
			desc:        "unknown file, type set, disposition set to attachment",
			key:         "something.dat",
			contentType: "unknown/thing",
			disposition: []string{"attachment; filename=something.dat"},
		},
		{
			desc:        "bin file, type set, disposition set to attachment",
			key:         "something.bin",
			contentType: "application/octet-stream",
			disposition: []string{"attachment; filename=something.bin"},
		},
		{
			desc: "pdf file, type detected, no disposition",
			key:  "test.pdf",
		},
		{
			desc:        "pdf file, type set, no disposition",
			key:         "test.pdf",
			contentType: "application/pdf",
		},
		{
			desc: "png file, type detected, no disposition",
			key:  "test.png",
		},
		{
			desc:        "html file, type detected, disposition set to attachment",
			key:         "test.html",
			disposition: []string{"attachment; filename=test.html"},
		},
		{
			desc:        "file with comma, type set, disposition set to attachment with quoted filename",
			key:         "test,file.dat",
			contentType: "unknown/thing",
			disposition: []string{"attachment; filename=\"test,file.dat\""},
		},
		{
			desc:        "file with UTF8, type set, disposition set to attachment with escaped filename",
			key:         "数据统计.png",
			contentType: "unknown/thing",
			disposition: []string{"attachment; filename*=utf-8''%E6%95%B0%E6%8D%AE%E7%BB%9F%E8%AE%A1.png"},
		},
		{
			desc:                   "html file, standard renders enabled, type detected, no disposition",
			key:                    "test.html",
			standardRendersContent: true,
		},
		{
			desc: "gif file, type detected, no disposition",
			key:  "test.gif",
		},
		{
			desc:                   "gif file, type detected, standard renders enabled, no disposition",
			key:                    "test.gif",
			standardRendersContent: true,
		},
		{
			desc:        "png file, type set, no disposition",
			key:         "something.else",
			contentType: "image/png",
		},
		{
			desc:        "hosting unknown file, type set, no disposition",
			key:         "something.dat",
			contentType: "unknown/thing",
			hosting:     true,
		},
		{
			desc:        "hosting bin file, type set, no disposition",
			key:         "test.bin",
			contentType: "application/binary-stream",
			hosting:     true,
		},
		{
			desc:    "hosting html file, type detected, no disposition",
			key:     "test.html",
			hosting: true,
		},
		{
			desc:        "hosting html file, type set, no disposition",
			key:         "test.html",
			contentType: "text/html",
			hosting:     true,
		},
		{
			desc:        "hosting png file, type set, no disposition",
			hosting:     true,
			key:         "test.png",
			contentType: "image/png",
		},
		{
			desc:                   "hosting png file, standard renders enabled, type set, no disposition",
			hosting:                true,
			standardRendersContent: true,
			key:                    "test.png",
			contentType:            "image/png",
		},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			cfg := Config{
				ListPageLimit:          1,
				URLBases:               []string{"http://test.test"},
				StandardRendersContent: tc.standardRendersContent,
			}

			handler, err := NewHandler(&zap.Logger{}, nil, nil, nil, cfg)
			require.NoError(t, err)

			ctx := testcontext.New(t)
			w := httptest.NewRecorder()
			r, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://test.test", nil)
			require.NoError(t, err)

			pr := &parsedRequest{hosting: tc.hosting}
			project := &uplink.Project{}

			var metadata uplink.CustomMetadata
			if tc.contentType != "" {
				metadata = uplink.CustomMetadata{"Content-Type": tc.contentType}
			}

			object := &uplink.Object{Key: tc.key, Custom: metadata}
			err = handler.showObject(ctx, w, r, pr, project, object, nil, httpranger.HTTPRange{})
			require.NoError(t, err)

			require.Equal(t, tc.disposition, w.Header()["Content-Disposition"])
		})
	}
}

func TestMetadataHeaderValue(t *testing.T) {
	assert.Equal(t, "", metadataHeaderValue(nil, "something"))
	assert.Equal(t, "", metadataHeaderValue(map[string]string{}, "something"))
	assert.Equal(t, "", metadataHeaderValue(map[string]string{"something": "value"}, ""))
	assert.Equal(t, "value", metadataHeaderValue(map[string]string{"something": "value"}, "something"))

	metadata := map[string]string{
		"Content-Type":  "value1",
		"content-type":  "value2",
		"Content-type":  "value3",
		"Cache-Control": "value4",
		"cache-control": "value5",
		"Cache-control": "value6",
	}

	assert.Equal(t, "value1", metadataHeaderValue(metadata, "Content-Type"))
	assert.Equal(t, "value4", metadataHeaderValue(metadata, "Cache-Control"))
	assert.Equal(t, "value1", metadataHeaderValue(metadata, "content-type"))
	assert.Equal(t, "value4", metadataHeaderValue(metadata, "cache-control"))
	assert.Equal(t, "value1", metadataHeaderValue(metadata, "Content-type"))
	assert.Equal(t, "value4", metadataHeaderValue(metadata, "Cache-control"))

	delete(metadata, "Content-Type")
	delete(metadata, "Cache-Control")

	assert.Equal(t, "value2", metadataHeaderValue(metadata, "Content-Type"))
	assert.Equal(t, "value5", metadataHeaderValue(metadata, "Cache-Control"))
	assert.Equal(t, "value2", metadataHeaderValue(metadata, "content-type"))
	assert.Equal(t, "value5", metadataHeaderValue(metadata, "cache-control"))
	assert.Equal(t, "value2", metadataHeaderValue(metadata, "Content-Type"))
	assert.Equal(t, "value5", metadataHeaderValue(metadata, "Cache-control"))

	delete(metadata, "content-type")
	delete(metadata, "cache-control")

	assert.Equal(t, "value3", metadataHeaderValue(metadata, "Content-Type"))
	assert.Equal(t, "value6", metadataHeaderValue(metadata, "Cache-Control"))
	assert.Equal(t, "value3", metadataHeaderValue(metadata, "content-type"))
	assert.Equal(t, "value6", metadataHeaderValue(metadata, "cache-control"))
	assert.Equal(t, "value3", metadataHeaderValue(metadata, "Content-type"))
	assert.Equal(t, "value6", metadataHeaderValue(metadata, "Cache-control"))
}

func TestContentType(t *testing.T) {
	testCases := []struct {
		desc       string
		key        string
		metadata   map[string]string
		detectType bool
		expected   string
	}{
		{
			desc:     "object with no metadata, no detection",
			key:      "test.gif",
			expected: "",
		},
		{
			desc:       "object with no metadata, type detected",
			key:        "test.gif",
			detectType: true,
			expected:   "image/gif",
		},
		{
			desc: "object with Content-Type metadata, no detection",
			key:  "test.svg",
			metadata: map[string]string{
				"Content-Type": "custom/mime",
			},
			expected: "custom/mime",
		},
		{
			desc: "object with content-type metadata, no detection",
			key:  "test.svg",
			metadata: map[string]string{
				"content-type": "custom/mime",
			},
			expected: "custom/mime",
		},
		{
			desc: "object with default content-type application/octet-stream, type detected",
			key:  "test.svg",
			metadata: map[string]string{
				"content-type": "application/octet-stream",
			},
			detectType: true,
			expected:   "image/svg+xml",
		},
		{
			desc: "object with default content-type binary/octet-stream, type detected",
			key:  "test.png",
			metadata: map[string]string{
				"content-type": "binary/octet-stream",
			},
			detectType: true,
			expected:   "image/png",
		},
		{
			desc: "object with default content-type application/octet-stream, no detection",
			key:  "test.png",
			metadata: map[string]string{
				"content-type": "application/octet-stream",
			},
			expected: "application/octet-stream",
		},
		{
			desc: "object with default content-type binary/octet-stream, no detection",
			key:  "test.png",
			metadata: map[string]string{
				"content-type": "binary/octet-stream",
			},
			expected: "binary/octet-stream",
		},
		{
			desc: "Content-Type overrides content-type, no detection",
			key:  "test.txt",
			metadata: map[string]string{
				"Content-Type": "text/html",
				"content-type": "text/plain",
			},
			expected: "text/html",
		},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			require.Equal(t, tc.expected, contentType(tc.key, tc.metadata, tc.detectType))
		})
	}
}

func TestHasValue(t *testing.T) {
	assert.False(t, hasValue(http.Header{}, "Content-Encoding", "gzip"))
	assert.False(t, hasValue(http.Header{"Content-Encoding": []string{"deflate", "gzip"}}, "Content-Encoding", "a"))
	assert.True(t, hasValue(http.Header{"Content-Encoding": []string{"deflate", "gzip"}}, "Content-Encoding", "deflate"))
	assert.True(t, hasValue(http.Header{"Content-Encoding": []string{"deflate", "gzip"}}, "Content-Encoding", "gzip"))
}

func TestZipArchiveContentType(t *testing.T) {
	cfg := Config{
		ListPageLimit: 1,
		URLBases:      []string{"http://test.test"},
	}
	handler, err := NewHandler(&zap.Logger{}, &objectmap.IPDB{}, nil, nil, cfg)
	require.NoError(t, err)
	handler.archiveRanger = func(_ context.Context, _ *uplink.Project, _, _, _ string, _ bool) (ranger.Ranger, bool, error) {
		return SimpleRanger(nil, 0), false, nil
	}
	ctx := testcontext.New(t)
	testZipItemContentType(ctx, t, handler, "test.txt", "bytes=0-", "text/plain; charset=utf-8", http.StatusRequestedRangeNotSatisfiable)
	testZipItemContentType(ctx, t, handler, "test.txt", "bytes=0-100", "text/plain; charset=utf-8", http.StatusRequestedRangeNotSatisfiable)
	testZipItemContentType(ctx, t, handler, "test.html", "", "text/plain", http.StatusOK) // by default, html isn't allowed for security reasons
	testZipItemContentType(ctx, t, handler, "test.jpg", "", "image/jpeg", http.StatusOK)
	testZipItemContentType(ctx, t, handler, "test.qwe", "", "application/octet-stream", http.StatusOK)
	testZipItemContentType(ctx, t, handler, "test", "", "application/octet-stream", http.StatusOK)
}

func testZipItemContentType(ctx context.Context, t *testing.T, handler *Handler, path, rangeStr, expectedCType string, expectedStatus int) {
	pr := &parsedRequest{}
	project := &uplink.Project{}
	object := &uplink.Object{Key: "test.zip"}
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://test.test?download&path="+path, nil)
	require.NoError(t, err)
	if len(rangeStr) > 0 {
		r.Header.Add("Range", rangeStr)
	}
	w := httptest.NewRecorder()

	err = handler.showObject(ctx, w, r, pr, project, object, nil, httpranger.HTTPRange{})

	if expectedStatus == http.StatusOK {
		require.NoError(t, err)
	} else {
		require.Error(t, err)
	}

	result := w.Result()

	require.Equal(t, expectedCType, result.Header.Get("Content-Type"))
	require.Equal(t, expectedStatus, errdata.GetStatus(err, http.StatusOK))
	require.NoError(t, result.Body.Close())
}

func TestImagePreviewPath(t *testing.T) {
	for i, tt := range [...]struct {
		key  string
		size int64

		wantTwitterImage string
		wantOgImage      string
	}{
		{
			key:              "key.jpeg",
			size:             100 * memory.KB.Int64(),
			wantTwitterImage: "raw/access/bucket/key.jpeg",
			wantOgImage:      "raw/access/bucket/key.jpeg",
		},

		{
			key:              "key.webp",
			size:             100 * memory.KB.Int64(),
			wantTwitterImage: "raw/access/bucket/key.webp",
			wantOgImage:      "",
		},
		{
			key:              "key.jpg",
			size:             4 * memory.MB.Int64(),
			wantTwitterImage: "",
			wantOgImage:      "raw/access/bucket/key.jpg",
		},

		{
			key:              "key.webp",
			size:             5 * memory.MB.Int64(),
			wantTwitterImage: "",
			wantOgImage:      "",
		},
		{
			key:              "key.rar",
			size:             6 * memory.KB.Int64(),
			wantTwitterImage: "",
			wantOgImage:      "",
		},
		{
			key:              "key.jpeg",
			size:             7 * memory.MB.Int64(),
			wantTwitterImage: "",
			wantOgImage:      "",
		},
	} {
		twitterImage, ogImage := imagePreviewPath("access", "bucket", tt.key, tt.size)
		assert.Equal(t, tt.wantTwitterImage, twitterImage, i)
		assert.Equal(t, tt.wantOgImage, ogImage, i)
	}
}

func TestIsDownloadAllowed(t *testing.T) {
	handler, err := NewHandler(&zap.Logger{}, &objectmap.IPDB{}, nil, nil, Config{
		ListPageLimit: 1,
		URLBases:      []string{"http://test.test"},
	})
	require.NoError(t, err)

	access, err := uplink.ParseAccess("1NfEFS9eR2QA5o6dov3QGNWrFRYZcufde1EcfS99cJB5ZewJZrWpJEZXat1d1GViu5R8G9NDjKz2z4nBUsmSyA6vPeUAnVheFARypytybCHCV8VcEPd1RyebPJ1apQQY8hNjk4r4v5Pe1sUULBERgemuPfcNMjMh5RUWfP1aNm7UFZToeV1ALKVKZCeetrnc8V2gaDz6R28Eaat62Xz7RBAmsfbJZ86GoDpw2PUrVMBGD9gtiRJiqTG7G")
	require.NoError(t, err)

	allowed := handler.isDownloadAllowed(access)
	require.True(t, allowed)

	downloadOnlyAccess, err := access.Share(
		uplink.Permission{AllowList: false, AllowDownload: true},
		uplink.SharePrefix{},
	)
	require.NoError(t, err)

	allowed = handler.isDownloadAllowed(downloadOnlyAccess)
	require.True(t, allowed)

	listOnlyAccess, err := access.Share(
		uplink.Permission{AllowList: true},
		uplink.SharePrefix{},
	)
	require.NoError(t, err)

	allowed = handler.isDownloadAllowed(listOnlyAccess)
	require.False(t, allowed)
}

func TestIsContentCodingAcceptable(t *testing.T) {
	require.Equal(t, true, isContentCodingAcceptable("gzip", http.Header{}))
	require.Equal(t, true, isContentCodingAcceptable("identity", http.Header{"Accept-Encoding": []string{""}}))

	for _, tt := range []struct {
		value    string
		accepted bool
	}{
		{"gzip", true},
		{"gzip, br", true},
		{"", false},
		{"*", true},
		{"*;q=0", false},
		{"*;q=0.1", true},
		{"gzip;q=0", false},
		{"gzip;q=0.1", true},
		{" GzIp ; Q = 0.1 ,", true},
		{"gzip, *;q=0", true},
	} {
		header := http.Header{"Accept-Encoding": []string{tt.value}}
		require.Equal(t, tt.accepted, isContentCodingAcceptable("gzip", header), "Header value: %s", tt.value)
	}
}
