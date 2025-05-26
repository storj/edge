// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package linksharing_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path"
	"slices"
	"strings"
	"testing"

	"github.com/foxcpp/go-mockdns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest"

	"storj.io/common/memory"
	"storj.io/common/rpc/rpcpool"
	"storj.io/common/rpc/rpctest"
	"storj.io/common/testcontext"
	"storj.io/common/testrand"
	"storj.io/common/uuid"
	"storj.io/edge/pkg/auth/authdb"
	"storj.io/edge/pkg/authclient"
	"storj.io/edge/pkg/linksharing/objectmap"
	"storj.io/edge/pkg/linksharing/sharing"
	"storj.io/edge/pkg/linksharing/sharing/assets"
	"storj.io/storj/private/testplanet"
	"storj.io/uplink"
)

func TestNewHandler(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	testCases := []struct {
		name   string
		config sharing.Config
		err    string
	}{
		{
			name: "URL base must be http or https",
			config: sharing.Config{
				URLBases:      []string{"gopher://chunks"},
				ListPageLimit: 100,
			},
			err: "URL base must be http:// or https://",
		},
		{
			name: "URL base must contain host",
			config: sharing.Config{
				URLBases:      []string{"http://"},
				ListPageLimit: 100,
			},
			err: "URL base must contain host",
		},
		{
			name: "URL base can have a port",
			config: sharing.Config{
				URLBases:      []string{"http://host:99"},
				ListPageLimit: 100,
			},
		},
		{
			name: "URL base can have a path",
			config: sharing.Config{
				URLBases:      []string{"http://host/gopher"},
				ListPageLimit: 100,
			},
		},
		{
			name: "URL base must not contain user info",
			config: sharing.Config{
				URLBases:      []string{"http://joe@host"},
				ListPageLimit: 100,
			},
			err: "URL base must not contain user info",
		},
		{
			name: "URL base must not contain query values",
			config: sharing.Config{
				URLBases:      []string{"http://host/?gopher=chunks"},
				ListPageLimit: 100,
			},
			err: "URL base must not contain query values",
		},
		{
			name: "URL base must not contain a fragment",
			config: sharing.Config{
				URLBases:      []string{"http://host/#gopher-chunks"},
				ListPageLimit: 100,
			},
			err: "URL base must not contain a fragment",
		},
	}

	mapper := objectmap.NewIPDB(&objectmap.MockReader{})

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			handler, err := sharing.NewHandler(zaptest.NewLogger(t), mapper, nil, nil, testCase.config)
			if testCase.err != "" {
				require.EqualError(t, err, testCase.err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, handler)
		})
	}
}

func TestHandlerRequests(t *testing.T) {
	testplanet.Run(t, testplanet.Config{
		SatelliteCount:   1,
		StorageNodeCount: 0,
		UplinkCount:      1,
		Reconfigure: testplanet.Reconfigure{
			SatelliteDBOptions: testplanet.SatelliteDBDisableCaches,
		},
	}, testHandlerRequests)
}

type authHandlerEntry struct {
	accessKey        string
	serializedAccess string
	publicProjectID  uuid.UUID
	public           bool
}

func testHandlerRequests(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet) {
	err := planet.Uplinks[0].Upload(ctx, planet.Satellites[0], "testbucket", "test/foo", []byte("FOOBAR"))
	require.NoError(t, err)

	testListPrefix := "pagination"
	for i := 0; i < 4; i++ {
		var name string
		if i == 3 {
			name = fmt.Sprintf("%s/%s", testListPrefix, sharing.FilePlaceholder)
		} else {
			name = fmt.Sprintf("%s/test%d", testListPrefix, i)
		}

		err = planet.Uplinks[0].Upload(ctx, planet.Satellites[0], "testbucket", name, []byte("FOOBAR"))
		require.NoError(t, err)
	}

	bandwidthLimit, err := planet.Satellites[0].DB.ProjectAccounting().GetProjectBandwidthLimit(ctx, planet.Uplinks[0].Projects[0].ID)
	require.NoError(t, err)

	access := planet.Uplinks[0].Access[planet.Satellites[0].ID()]
	serializedAccess, err := access.Serialize()
	require.NoError(t, err)

	listOnlyAccess, err := access.Share(
		uplink.Permission{AllowList: true},
		uplink.SharePrefix{Bucket: "testbucket", Prefix: "test/foo"},
	)
	require.NoError(t, err)

	serializedListOnlyAccess, err := listOnlyAccess.Serialize()
	require.NoError(t, err)

	prefixedAccess, err := access.Share(
		uplink.Permission{AllowList: true},
		uplink.SharePrefix{Bucket: "testbucket", Prefix: "test/"},
	)
	require.NoError(t, err)

	serializedPrefixedAccess, err := prefixedAccess.Serialize()
	require.NoError(t, err)

	downloadOnlyAccess, err := access.Share(
		uplink.Permission{AllowList: false, AllowDownload: true},
		uplink.SharePrefix{Bucket: "testbucket"},
	)
	require.NoError(t, err)

	serializedDownloadOnlyAccess, err := downloadOnlyAccess.Serialize()
	require.NoError(t, err)

	missingAccessName := randomAccessKey(t)
	goodAccessName := randomAccessKey(t)
	privateAccessName := randomAccessKey(t)
	listOnlyAccessName := randomAccessKey(t)
	prefixedAccessName := randomAccessKey(t)
	downloadOnlyAccessName := randomAccessKey(t)

	authToken := hex.EncodeToString(testrand.BytesInt(16))
	validAuthServer := httptest.NewServer(makeAuthHandler(t, []authHandlerEntry{
		{goodAccessName, serializedAccess, testrand.UUID(), true},
		{privateAccessName, serializedAccess, testrand.UUID(), false},
		{listOnlyAccessName, serializedListOnlyAccess, testrand.UUID(), true},
		{prefixedAccessName, serializedPrefixedAccess, testrand.UUID(), true},
		{downloadOnlyAccessName, serializedDownloadOnlyAccess, testrand.UUID(), true},
	}, authToken))
	defer validAuthServer.Close()

	type listPageLimit struct {
		v int
	}

	testCases := []struct {
		name                  string
		host                  string
		method                string
		path                  string
		dnsRecords            map[string]mockdns.Zone
		redirectLocation      string
		status                int
		reqHeader             map[string]string
		body                  []string
		notContains           []string
		downloadPrefixEnabled bool
		zipContent            map[string]string
		tarContent            map[string]string
		listPageLimit         *listPageLimit
		newHandlerErr         error
		authserver            string
		expectedRPCCalls      []string
		prepFunc              func() error
		cleanupFunc           func() error
	}{
		{
			name:             "GET missing access",
			method:           "GET",
			path:             "s/",
			status:           http.StatusBadRequest,
			body:             []string{"Malformed request."},
			expectedRPCCalls: []string{},
		},
		{
			name:             "GET misconfigured auth server",
			method:           "GET",
			path:             path.Join("s", goodAccessName, "testbucket", "test/foo"),
			status:           http.StatusInternalServerError,
			body:             []string{"Internal server error."},
			authserver:       "invalid://",
			expectedRPCCalls: []string{},
		},
		{
			name:             "GET missing access key",
			method:           "GET",
			path:             path.Join("s", missingAccessName, "testbucket", "test/foo"),
			status:           http.StatusUnauthorized,
			body:             []string{"Access denied."},
			authserver:       validAuthServer.URL,
			expectedRPCCalls: []string{},
		},
		{
			name:             "GET private access key",
			method:           "GET",
			path:             path.Join("s", privateAccessName, "testbucket", "test/foo"),
			status:           http.StatusForbidden,
			body:             []string{"Access denied."},
			authserver:       validAuthServer.URL,
			expectedRPCCalls: []string{},
		},
		{
			name:             "GET found access key",
			method:           "GET",
			path:             path.Join("s", goodAccessName, "testbucket", "test/foo"),
			status:           http.StatusOK,
			body:             []string{"foo"},
			authserver:       validAuthServer.URL,
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* GetObject */, "/metainfo.Metainfo/GetObjectIPs"},
		},
		{
			name:             "GET missing bucket",
			method:           "GET",
			path:             path.Join("s", serializedAccess),
			status:           http.StatusBadRequest,
			body:             []string{"Malformed request."},
			expectedRPCCalls: []string{},
		},
		{
			name:             "GET object not found",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", "test/bar"),
			status:           http.StatusNotFound,
			body:             []string{"Object not found"},
			expectedRPCCalls: slices.Repeat([]string{"/metainfo.Metainfo/CompressedBatch"}, 3), // GetObject, GetObject, ListObjects
		},
		{
			name:             "GET success",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", "test/foo"),
			status:           http.StatusOK,
			body:             []string{"foo"},
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* GetObject */, "/metainfo.Metainfo/GetObjectIPs"},
		},
		{
			name:             "GET download",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", "test/foo?download=1"),
			status:           http.StatusOK,
			body:             []string{"FOOBAR"},
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* DownloadObject */},
		},
		{
			name:             "GET map only",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", "test/foo?map=1"),
			status:           http.StatusOK,
			body:             []string{"circle"},
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* GetObject */, "/metainfo.Metainfo/GetObjectIPs"},
		},
		{
			name:             "GET map only raw",
			method:           "GET",
			path:             path.Join("raw", serializedAccess, "testbucket", "test/foo?map=1"),
			status:           http.StatusOK,
			body:             []string{"circle"},
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* GetObject */, "/metainfo.Metainfo/GetObjectIPs"},
		},
		{
			name:             "GET view",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", "test/foo?view=1"),
			status:           http.StatusOK,
			body:             []string{"FOOBAR"},
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* DownloadObject */},
		},
		{
			name:             "GET wrap",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", "test/foo?wrap=1"),
			status:           http.StatusOK,
			body:             []string{"This file is ready for download"},
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* GetObject */, "/metainfo.Metainfo/GetObjectIPs"},
		},
		{
			name:   "GET wrap (image preview)",
			method: "GET",
			path:   path.Join("s", serializedAccess, "testbucket", "test/mIllogh.jpg?wrap=1"),
			status: http.StatusOK,
			body: []string{
				`<meta property="og:image" content="http://localhost/raw/` + serializedAccess + `/testbucket/test/mIllogh.jpg?v=" />`,
				`<meta name="twitter:image" content="http://localhost/raw/` + serializedAccess + `/testbucket/test/mIllogh.jpg?v=" />`,
			},
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* GetObject */, "/metainfo.Metainfo/GetObjectIPs"},
			prepFunc: func() error {
				return planet.Uplinks[0].Upload(ctx, planet.Satellites[0], "testbucket", "test/mIllogh.jpg", []byte("mIllogh"))
			},
			cleanupFunc: func() error {
				return planet.Uplinks[0].DeleteObject(ctx, planet.Satellites[0], "testbucket", "test/mIllogh.jpg")
			},
		},
		{
			name:             "GET wrap raw",
			method:           "GET",
			path:             path.Join("raw", serializedAccess, "testbucket", "test/foo?wrap=1"),
			status:           http.StatusOK,
			body:             []string{"This file is ready for download"},
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* GetObject */, "/metainfo.Metainfo/GetObjectIPs"},
		},
		{
			name:   "GET wrap raw (image preview)",
			method: "GET",
			path:   path.Join("raw", serializedAccess, "testbucket", "test/mIllogh.jpg?wrap=1"),
			status: http.StatusOK,
			body: []string{
				`<meta property="og:image" content="http://localhost/raw/` + serializedAccess + `/testbucket/test/mIllogh.jpg?v=" />`,
				`<meta name="twitter:image" content="http://localhost/raw/` + serializedAccess + `/testbucket/test/mIllogh.jpg?v=" />`,
			},
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* GetObject */, "/metainfo.Metainfo/GetObjectIPs"},
			prepFunc: func() error {
				return planet.Uplinks[0].Upload(ctx, planet.Satellites[0], "testbucket", "test/mIllogh.jpg", []byte("mIllogh"))
			},
			cleanupFunc: func() error {
				return planet.Uplinks[0].DeleteObject(ctx, planet.Satellites[0], "testbucket", "test/mIllogh.jpg")
			},
		},
		{
			name:             "GET no wrap",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", "test/foo?wrap=no"),
			status:           http.StatusOK,
			body:             []string{"FOOBAR"},
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* DownloadObject */},
		},
		{
			name:             "GET download success",
			method:           "GET",
			path:             path.Join("raw", serializedAccess, "testbucket", "test/foo"),
			status:           http.StatusOK,
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* DownloadObject */},
		},
		{
			name:   "GET download with range",
			method: "GET",
			path:   path.Join("raw", serializedAccess, "testbucket", "test/foo"),
			reqHeader: map[string]string{
				"Range": "bytes=0-",
			},
			status:           http.StatusPartialContent,
			body:             []string{"FOOBAR"},
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* DownloadObject */},
		},
		{
			name:   "GET download with range partial content",
			method: "GET",
			path:   path.Join("raw", serializedAccess, "testbucket", "test/foo"),
			reqHeader: map[string]string{
				"Range": "bytes=0-1",
			},
			status:           http.StatusPartialContent,
			body:             []string{"FO"},
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* DownloadObject */},
		},
		{
			name:   "GET download with suffix-byte-range",
			method: "GET",
			path:   path.Join("raw", serializedAccess, "testbucket", "test/foo"),
			reqHeader: map[string]string{
				"Range": "bytes=-3",
			},
			status:           http.StatusPartialContent,
			body:             []string{"BAR"},
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* DownloadObject */},
		},
		{
			name:   "GET download with too large range",
			method: "GET",
			path:   path.Join("raw", serializedAccess, "testbucket", "test/foo"),
			reqHeader: map[string]string{
				"Range": "bytes=0-10",
			},
			status:           http.StatusPartialContent,
			body:             []string{"FOO"},
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* DownloadObject */},
		},
		{
			name:   "GET download not modified modtime",
			method: "GET",
			path:   path.Join("raw", serializedAccess, "testbucket", "test/foo"),
			reqHeader: map[string]string{
				"If-Modified-Since": "Wed, 25 Jun 2100 17:12:18 GMT",
			},
			status:           http.StatusNotModified,
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* DownloadObject */},
		},
		{
			name:   "GET download with range no overlap",
			method: "GET",
			path:   path.Join("raw", serializedAccess, "testbucket", "test/foo"),
			reqHeader: map[string]string{
				"Range": "bytes=10-20",
			},
			status:           http.StatusRequestedRangeNotSatisfiable,
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* DownloadObject */},
		},
		{
			name:   "GET download range with modtime mismatch",
			method: "GET",
			path:   path.Join("raw", serializedAccess, "testbucket", "test/foo"),
			reqHeader: map[string]string{
				"Range":    "bytes=0-4",
				"If-Range": "Wed, 25 Jun 2014 17:12:18 GMT",
			},
			status:           http.StatusOK,
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* DownloadObject */, "/metainfo.Metainfo/CompressedBatch" /* DownloadObject */},
		},
		{
			name:       "GET download with trailing slash",
			method:     "GET",
			path:       path.Join("raw", goodAccessName, "testbucket", "test/foo1") + "/",
			status:     http.StatusOK,
			body:       []string{"FOO"},
			authserver: validAuthServer.URL,
			// todo(sean): sometimes this responds with different results. For example:
			// * []string{"/metainfo.Metainfo/CompressedBatch" /* GetObject */, "/metainfo.Metainfo/CompressedBatch" /* DownloadObject */}
			// * []string{"/metainfo.Metainfo/CompressedBatch" /* GetObject */, "/metainfo.Metainfo/CompressedBatch" /* DownloadObject */, "/metainfo.Metainfo/CompressedBatch" /* GetObject */}
			//
			// expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* GetObject */, "/metainfo.Metainfo/CompressedBatch" /* GetObject */, "/metainfo.Metainfo/CompressedBatch" /* DownloadObject */},
			prepFunc: func() error {
				return planet.Uplinks[0].Upload(ctx, planet.Satellites[0], "testbucket", "test/foo1/", []byte("FOO"))
			},
			cleanupFunc: func() error {
				return planet.Uplinks[0].DeleteObject(ctx, planet.Satellites[0], "testbucket", "test/foo1/")
			},
		},
		{
			name:             "GET bucket listing success",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket") + "/",
			status:           http.StatusOK,
			body:             []string{"test/"},
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* ListObjects */},
		},
		{
			name:             "GET prefix listing success",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", "test") + "/",
			status:           http.StatusOK,
			body:             []string{"foo"},
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* GetObject */, "/metainfo.Metainfo/CompressedBatch" /* GetObject */, "/metainfo.Metainfo/CompressedBatch" /* ListObjects */},
		},
		{
			name:             "GET prefix listing success page 1 limit 1",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", testListPrefix) + "/",
			status:           http.StatusOK,
			body:             []string{"test0", "Next", "?cursor=test0"},
			notContains:      []string{"test1", "test2", sharing.FilePlaceholder, "Back To Page 1", "history.back()"},
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* GetObject */, "/metainfo.Metainfo/CompressedBatch" /* GetObject */, "/metainfo.Metainfo/CompressedBatch" /* ListObjects */},
		},
		{
			name:             "GET prefix listing success page 2 limit 1",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", testListPrefix, "?cursor=test0"),
			status:           http.StatusOK,
			body:             []string{"test2", "Next", "?cursor=test2", "Back To Page 1", "history.back()"},
			notContains:      []string{"test0", "test1", sharing.FilePlaceholder},
			expectedRPCCalls: slices.Repeat([]string{"/metainfo.Metainfo/CompressedBatch"}, 3), // GetObject, GetObject, ListObjects
		},
		{
			name:             "GET prefix listing success page 3 limit 1; is final page since next page would only contain FilePlaceholder.",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", testListPrefix, "?cursor=test2"),
			status:           http.StatusOK,
			body:             []string{"test1", "Back To Page 1", "history.back()"},
			notContains:      []string{"test2", "test0", "Next", sharing.FilePlaceholder},
			expectedRPCCalls: slices.Repeat([]string{"/metainfo.Metainfo/CompressedBatch"}, 3),
		},
		{
			name:             "GET prefix listing success page 3 limit 1; is not final page since next page contains more than just FilePlaceholder.",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", testListPrefix, "?cursor=test2"),
			status:           http.StatusOK,
			body:             []string{"test1", "Back To Page 1", "history.back()"},
			notContains:      []string{"test2", "test0", sharing.FilePlaceholder},
			expectedRPCCalls: slices.Repeat([]string{"/metainfo.Metainfo/CompressedBatch"}, 3),
			prepFunc: func() error {
				return planet.Uplinks[0].Upload(ctx, planet.Satellites[0], "testbucket", fmt.Sprintf("%s/%s", testListPrefix, ".foo"), []byte("FOO"))
			},
		},
		{
			name:             "GET prefix listing success page 4 limit 1",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", testListPrefix, "?cursor=test1"),
			status:           http.StatusOK,
			body:             []string{".foo", "Back To Page 1", "history.back()"},
			notContains:      []string{"test1", "test2", "test0", "Next", sharing.FilePlaceholder},
			expectedRPCCalls: slices.Repeat([]string{"/metainfo.Metainfo/CompressedBatch"}, 3),
		},
		{
			name:             "GET prefix listing success page 1 limit 2",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", testListPrefix) + "/",
			status:           http.StatusOK,
			listPageLimit:    &listPageLimit{v: 2},
			body:             []string{"test0", "test2", "Next", "?cursor=test2"},
			notContains:      []string{"test1", ".foo", "Back To Page 1", "history.back()", sharing.FilePlaceholder},
			expectedRPCCalls: slices.Repeat([]string{"/metainfo.Metainfo/CompressedBatch"}, 3),
		},
		{
			name:             "GET prefix listing success page 2 limit 2",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", testListPrefix, "?cursor=test2"),
			status:           http.StatusOK,
			listPageLimit:    &listPageLimit{v: 2},
			body:             []string{"test1", ".foo", "Back To Page 1", "history.back()"},
			notContains:      []string{"test0", "test2", "Next", sharing.FilePlaceholder},
			expectedRPCCalls: slices.Repeat([]string{"/metainfo.Metainfo/CompressedBatch"}, 3),
		},
		{
			name:   "GET directory listing shows link to parent directory",
			method: "GET",
			path:   path.Join("s", serializedAccess, "testbucket", "test") + "/",
			status: http.StatusOK,
			body:   []string{"..."},
		},
		{
			name:        "GET directory listing hides link to unlistable parent directory",
			method:      "GET",
			path:        path.Join("s", serializedPrefixedAccess, "testbucket", "test") + "/",
			status:      http.StatusOK,
			notContains: []string{"..."},
		},
		{
			name:             "GET prefix listing with cursor at last object fails",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", testListPrefix, "?cursor=.foo"),
			status:           http.StatusNotFound,
			notContains:      []string{"test0", "test1", "test2", ".foo", sharing.FilePlaceholder},
			expectedRPCCalls: slices.Repeat([]string{"/metainfo.Metainfo/CompressedBatch"}, 3),
		},
		{
			name:          "List page limit of 0 should error",
			listPageLimit: &listPageLimit{v: 0},
			newHandlerErr: sharing.ErrInvalidListPageLimit,
		},
		{
			name:          "List page limit of -1 should error",
			listPageLimit: &listPageLimit{v: -1},
			newHandlerErr: sharing.ErrInvalidListPageLimit,
		},
		{
			name:             "GET prefix listing empty",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", "test-empty") + "/",
			status:           http.StatusNotFound,
			expectedRPCCalls: slices.Repeat([]string{"/metainfo.Metainfo/CompressedBatch"}, 3),
		},
		{
			name:             "GET prefix redirect",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", "test"),
			status:           http.StatusSeeOther,
			redirectLocation: "http://localhost/" + path.Join("s", serializedAccess, "testbucket", "test") + "/",
			expectedRPCCalls: slices.Repeat([]string{"/metainfo.Metainfo/CompressedBatch"}, 3),
		},
		{
			name:             "GET list-only access grant",
			method:           "GET",
			path:             path.Join("s", serializedListOnlyAccess, "testbucket", "test/foo"),
			status:           http.StatusOK,
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* GetObject */, "/metainfo.Metainfo/GetObjectIPs"},
		},
		{
			name:             "GET download list-only access grant",
			method:           "GET",
			path:             path.Join("raw", serializedListOnlyAccess, "testbucket", "test/foo"),
			status:           http.StatusForbidden,
			body:             []string{"Access denied"},
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* DownloadObject */},
		},
		{
			name:             "HEAD missing access",
			method:           "HEAD",
			path:             "s/",
			status:           http.StatusBadRequest,
			body:             []string{"Malformed request."},
			expectedRPCCalls: []string{},
		},
		{
			name:             "HEAD misconfigured auth server",
			method:           "HEAD",
			path:             path.Join("s", goodAccessName, "testbucket", "test/foo"),
			status:           http.StatusInternalServerError,
			body:             []string{"Internal server error."},
			authserver:       "invalid://",
			expectedRPCCalls: []string{},
		},
		{
			name:             "HEAD missing access key",
			method:           "HEAD",
			path:             path.Join("s", missingAccessName, "testbucket", "test/foo"),
			status:           http.StatusUnauthorized,
			body:             []string{"Access denied."},
			authserver:       validAuthServer.URL,
			expectedRPCCalls: []string{},
		},
		{
			name:             "HEAD private access key",
			method:           "GET",
			path:             path.Join("s", privateAccessName, "testbucket", "test/foo"),
			status:           http.StatusForbidden,
			body:             []string{"Access denied"},
			authserver:       validAuthServer.URL,
			expectedRPCCalls: []string{},
		},
		{
			name:             "HEAD found access key",
			method:           "GET",
			path:             path.Join("s", goodAccessName, "testbucket", "test/foo"),
			status:           http.StatusOK,
			body:             []string{""},
			authserver:       validAuthServer.URL,
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* GetObject */, "/metainfo.Metainfo/GetObjectIPs"},
		},
		{
			name:             "HEAD missing bucket",
			method:           "HEAD",
			path:             path.Join("s", serializedAccess),
			status:           http.StatusBadRequest,
			body:             []string{"Malformed request."},
			expectedRPCCalls: []string{},
		},
		{
			name:             "HEAD object not found",
			method:           "HEAD",
			path:             path.Join("s", serializedAccess, "testbucket", "test/bar"),
			status:           http.StatusNotFound,
			body:             []string{"Object not found"},
			expectedRPCCalls: slices.Repeat([]string{"/metainfo.Metainfo/CompressedBatch"}, 3),
		},
		{
			name:             "HEAD success",
			method:           "HEAD",
			path:             path.Join("s", serializedAccess, "testbucket", "test/foo"),
			status:           http.StatusOK,
			body:             []string{""},
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* GetObject */, "/metainfo.Metainfo/GetObjectIPs"},
		},
		{
			name:             "GET download when exceeded bandwidth limit",
			method:           "GET",
			path:             path.Join("raw", serializedAccess, "testbucket", "test/foo"),
			status:           http.StatusForbidden,
			body:             []string{"Bandwidth limit exceeded"},
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* DownloadObject */},
			prepFunc: func() error {
				// set bandwidth limit to 0
				return planet.Satellites[0].DB.ProjectAccounting().UpdateProjectBandwidthLimit(ctx, planet.Uplinks[0].Projects[0].ID, 0)
			},
			cleanupFunc: func() error {
				// set bandwidth limit back to initial value
				return planet.Satellites[0].DB.ProjectAccounting().UpdateProjectBandwidthLimit(ctx, planet.Uplinks[0].Projects[0].ID, memory.Size(*bandwidthLimit))
			},
		},
		{
			name:             "GET prefix download-only access",
			method:           "GET",
			path:             path.Join("s", downloadOnlyAccessName, "testbucket", "test/bar") + "/",
			status:           http.StatusForbidden,
			authserver:       validAuthServer.URL,
			expectedRPCCalls: slices.Repeat([]string{"/metainfo.Metainfo/CompressedBatch"}, 3),
		},
		{
			name:             "GET prefix containing index.html",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", "test/bar") + "/",
			status:           http.StatusOK,
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* GetObject */, "/metainfo.Metainfo/CompressedBatch" /* GetObject */, "/metainfo.Metainfo/GetObjectIPs"},
			prepFunc: func() error {
				return planet.Uplinks[0].Upload(ctx, planet.Satellites[0], "testbucket", "test/bar/index.html", []byte("HELLO!"))
			},
			cleanupFunc: func() error {
				return planet.Uplinks[0].DeleteObject(ctx, planet.Satellites[0], "testbucket", "test/bar/index.html")
			},
		},
		{
			name:             "GET prefix containing index.html download-only access",
			method:           "GET",
			path:             path.Join("s", downloadOnlyAccessName, "testbucket", "test/bar") + "/",
			status:           http.StatusOK,
			authserver:       validAuthServer.URL,
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* GetObject */, "/metainfo.Metainfo/CompressedBatch" /* GetObject */, "/metainfo.Metainfo/GetObjectIPs"},
			prepFunc: func() error {
				return planet.Uplinks[0].Upload(ctx, planet.Satellites[0], "testbucket", "test/bar/index.html", []byte("HELLO!"))
			},
			cleanupFunc: func() error {
				return planet.Uplinks[0].DeleteObject(ctx, planet.Satellites[0], "testbucket", "test/bar/index.html")
			},
		},
		{
			name:             "hosting GET missing all TXT records",
			host:             "mydomain.com",
			method:           "GET",
			status:           http.StatusBadRequest,
			body:             []string{"Malformed request."},
			authserver:       validAuthServer.URL,
			expectedRPCCalls: []string{},
		},
		{
			name:   "hosting GET empty access TXT record",
			host:   "mydomain.com",
			method: "GET",
			dnsRecords: map[string]mockdns.Zone{
				"txt-mydomain.com.": {
					TXT: []string{
						"storj-root:testbucket",
					},
				},
			},
			status:           http.StatusBadRequest,
			body:             []string{"Malformed request."},
			authserver:       validAuthServer.URL,
			expectedRPCCalls: []string{},
		},
		{
			name:   "hosting GET empty root TXT record",
			host:   "mydomain.com",
			method: "GET",
			dnsRecords: map[string]mockdns.Zone{
				"txt-mydomain.com.": {
					TXT: []string{
						"storj-access:" + goodAccessName,
					},
				},
			},
			status:           http.StatusBadRequest,
			body:             []string{"Invalid bucket name."},
			authserver:       validAuthServer.URL,
			expectedRPCCalls: []string{},
		},
		{
			name:   "hosting GET private access key",
			host:   "mydomain.com",
			method: "GET",
			dnsRecords: map[string]mockdns.Zone{
				"txt-mydomain.com.": {
					TXT: []string{
						"storj-access:" + privateAccessName,
						"storj-root:testbucket",
					},
				},
			},
			status:           http.StatusForbidden,
			body:             []string{"Access denied."},
			authserver:       validAuthServer.URL,
			expectedRPCCalls: []string{},
		},
		{
			name:   "hosting GET download list-only access",
			host:   "mydomain.com",
			method: "GET",
			dnsRecords: map[string]mockdns.Zone{
				"txt-mydomain.com.": {
					TXT: []string{
						"storj-access:" + listOnlyAccessName,
						"storj-root:testbucket/test/foo",
					},
				},
			},
			status:           http.StatusForbidden,
			authserver:       validAuthServer.URL,
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* DownloadObject */},
		},
		{
			name:   "hosting GET prefix download-only access",
			host:   "mydomain.com",
			method: "GET",
			path:   "test/foo/",
			dnsRecords: map[string]mockdns.Zone{
				"txt-mydomain.com.": {
					TXT: []string{
						"storj-access:" + downloadOnlyAccessName,
						"storj-root:testbucket",
					},
				},
			},
			status:           http.StatusForbidden,
			authserver:       validAuthServer.URL,
			expectedRPCCalls: slices.Repeat([]string{"/metainfo.Metainfo/CompressedBatch"}, 3),
		},
		{
			name:   "hosting GET root index.html download-only access",
			host:   "mydomain.com",
			method: "GET",
			dnsRecords: map[string]mockdns.Zone{
				"txt-mydomain.com.": {
					TXT: []string{
						"storj-access:" + downloadOnlyAccessName,
						"storj-root:testbucket",
					},
				},
			},
			status:           http.StatusOK,
			body:             []string{"HELLO!"},
			authserver:       validAuthServer.URL,
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* DownloadObject */},
			prepFunc: func() error {
				return planet.Uplinks[0].Upload(ctx, planet.Satellites[0], "testbucket", "index.html", []byte("HELLO!"))
			},
			cleanupFunc: func() error {
				return planet.Uplinks[0].DeleteObject(ctx, planet.Satellites[0], "testbucket", "index.html")
			},
		},
		{
			name:   "hosting GET root index.html",
			host:   "mydomain.com",
			method: "GET",
			dnsRecords: map[string]mockdns.Zone{
				"txt-mydomain.com.": {
					TXT: []string{
						"storj-access:" + goodAccessName,
						"storj-root:testbucket",
					},
				},
			},
			status:           http.StatusOK,
			body:             []string{"HELLO!"},
			authserver:       validAuthServer.URL,
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* DownloadObject */},
			prepFunc: func() error {
				return planet.Uplinks[0].Upload(ctx, planet.Satellites[0], "testbucket", "index.html", []byte("HELLO!"))
			},
			cleanupFunc: func() error {
				return planet.Uplinks[0].DeleteObject(ctx, planet.Satellites[0], "testbucket", "index.html")
			},
		},
		{
			name:   "hosting GET prefix index.html",
			host:   "mydomain.com",
			method: "GET",
			dnsRecords: map[string]mockdns.Zone{
				"txt-mydomain.com.": {
					TXT: []string{
						"storj-access:" + goodAccessName,
						"storj-root:testbucket/prefix",
					},
				},
			},
			status:           http.StatusOK,
			body:             []string{"HELLO!"},
			authserver:       validAuthServer.URL,
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* DownloadObject */},
			prepFunc: func() error {
				return planet.Uplinks[0].Upload(ctx, planet.Satellites[0], "testbucket", "prefix/index.html", []byte("HELLO!"))
			},
			cleanupFunc: func() error {
				return planet.Uplinks[0].DeleteObject(ctx, planet.Satellites[0], "testbucket", "prefix/index.html")
			},
		},
		{
			name:   "hosting GET success",
			host:   "mydomain.com",
			method: "GET",
			path:   "foo",
			dnsRecords: map[string]mockdns.Zone{
				"txt-mydomain.com.": {
					TXT: []string{
						"storj-access:" + goodAccessName,
						"storj-root:testbucket/test",
					},
				},
			},
			status:           http.StatusOK,
			body:             []string{"FOO"},
			authserver:       validAuthServer.URL,
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* DownloadObject */},
		},
		{
			name:   "hosting GET success (image preview)",
			host:   "mydomain.com",
			method: "GET",
			path:   "mIllogh.jpg?wrap=1",
			dnsRecords: map[string]mockdns.Zone{
				"txt-mydomain.com.": {
					TXT: []string{
						"storj-access:" + goodAccessName,
						"storj-root:testbucket/test",
					},
				},
			},
			status: http.StatusOK,
			body: []string{
				`<meta property="og:image" content="http://localhost/raw/` + goodAccessName + `/testbucket/test/mIllogh.jpg?v=" />`,
				`<meta name="twitter:image" content="http://localhost/raw/` + goodAccessName + `/testbucket/test/mIllogh.jpg?v=" />`,
			},
			authserver:       validAuthServer.URL,
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* GetObject */, "/metainfo.Metainfo/GetObjectIPs"},
			prepFunc: func() error {
				return planet.Uplinks[0].Upload(ctx, planet.Satellites[0], "testbucket", "test/mIllogh.jpg", []byte("mIllogh"))
			},
			cleanupFunc: func() error {
				return planet.Uplinks[0].DeleteObject(ctx, planet.Satellites[0], "testbucket", "test/mIllogh.jpg")
			},
		},
		{
			name:   "hosting GET root 404 default page",
			host:   "mydomain.com",
			method: "GET",
			path:   "/doesnotexist",
			dnsRecords: map[string]mockdns.Zone{
				"txt-mydomain.com.": {
					TXT: []string{
						"storj-access:" + goodAccessName,
						"storj-root:testbucket",
					},
				},
			},
			status:           http.StatusNotFound,
			body:             []string{"Object not found"},
			authserver:       validAuthServer.URL,
			expectedRPCCalls: slices.Repeat([]string{"/metainfo.Metainfo/CompressedBatch"}, 4),
		},
		{
			name:   "hosting GET root 404.html",
			host:   "mydomain.com",
			method: "GET",
			path:   "/doesnotexist",
			dnsRecords: map[string]mockdns.Zone{
				"txt-mydomain.com.": {
					TXT: []string{
						"storj-access:" + goodAccessName,
						"storj-root:testbucket",
					},
				},
			},
			status:           http.StatusNotFound,
			body:             []string{"NOT FOUND!"},
			authserver:       validAuthServer.URL,
			expectedRPCCalls: slices.Repeat([]string{"/metainfo.Metainfo/CompressedBatch"}, 4),
			prepFunc: func() error {
				return planet.Uplinks[0].Upload(ctx, planet.Satellites[0], "testbucket", "404.html", []byte("NOT FOUND!"))
			},
			cleanupFunc: func() error {
				return planet.Uplinks[0].DeleteObject(ctx, planet.Satellites[0], "testbucket", "404.html")
			},
		},
		{
			name:                  "GET bucket zip download",
			method:                "GET",
			path:                  path.Join("s", serializedAccess, "testbucket", "?download=1"),
			status:                http.StatusOK,
			downloadPrefixEnabled: true,
			zipContent: map[string]string{
				"test/foo":                     "FOOBAR",
				"pagination/.foo":              "FOO",
				"pagination/.file_placeholder": "FOOBAR",
				"pagination/test0":             "FOOBAR",
				"pagination/test1":             "FOOBAR",
				"pagination/test2":             "FOOBAR",
			},
			expectedRPCCalls: slices.Repeat([]string{"/metainfo.Metainfo/CompressedBatch"}, 7),
		},
		{
			name:                  "GET bucket tar download",
			method:                "GET",
			path:                  path.Join("s", serializedAccess, "testbucket", "?download=1&download-kind=tar.gz"),
			status:                http.StatusOK,
			downloadPrefixEnabled: true,
			tarContent: map[string]string{
				"test/foo":                     "FOOBAR",
				"pagination/.foo":              "FOO",
				"pagination/.file_placeholder": "FOOBAR",
				"pagination/test0":             "FOOBAR",
				"pagination/test1":             "FOOBAR",
				"pagination/test2":             "FOOBAR",
			},
			expectedRPCCalls: slices.Repeat([]string{"/metainfo.Metainfo/CompressedBatch"}, 7),
		},
		{
			name:                  "GET prefix zip download",
			method:                "GET",
			path:                  path.Join("s", serializedAccess, "testbucket", "test/?download=1"),
			status:                http.StatusOK,
			downloadPrefixEnabled: true,
			zipContent:            map[string]string{"foo": "FOOBAR"},
			expectedRPCCalls:      slices.Repeat([]string{"/metainfo.Metainfo/CompressedBatch"}, 4),
		},
		{
			name:                  "GET prefix tar download",
			method:                "GET",
			path:                  path.Join("s", serializedAccess, "testbucket", "test/?download=1&download-kind=tar.gz"),
			status:                http.StatusOK,
			downloadPrefixEnabled: true,
			tarContent:            map[string]string{"foo": "FOOBAR"},
			expectedRPCCalls:      slices.Repeat([]string{"/metainfo.Metainfo/CompressedBatch"}, 4),
		},
		{
			name:                  "GET prefix zip download bandwidth limit",
			method:                "GET",
			path:                  path.Join("s", serializedAccess, "testbucket", "test/?download=1"),
			status:                http.StatusForbidden,
			downloadPrefixEnabled: true,
			body:                  []string{"Bandwidth limit exceeded"},
			expectedRPCCalls:      slices.Repeat([]string{"/metainfo.Metainfo/CompressedBatch"}, 4),
			prepFunc: func() error {
				// set bandwidth limit to 0
				return planet.Satellites[0].DB.ProjectAccounting().UpdateProjectBandwidthLimit(ctx, planet.Uplinks[0].Projects[0].ID, 0)
			},
			cleanupFunc: func() error {
				// set bandwidth limit back to initial value
				return planet.Satellites[0].DB.ProjectAccounting().UpdateProjectBandwidthLimit(ctx, planet.Uplinks[0].Projects[0].ID, memory.Size(*bandwidthLimit))
			},
		},
		{
			name:                  "GET prefix tar download bandwidth limit",
			method:                "GET",
			path:                  path.Join("s", serializedAccess, "testbucket", "test/?download=1&download-kind=tar.gz"),
			status:                http.StatusForbidden,
			downloadPrefixEnabled: true,
			body:                  []string{"Bandwidth limit exceeded"},
			expectedRPCCalls:      slices.Repeat([]string{"/metainfo.Metainfo/CompressedBatch"}, 4),
			prepFunc: func() error {
				// set bandwidth limit to 0
				return planet.Satellites[0].DB.ProjectAccounting().UpdateProjectBandwidthLimit(ctx, planet.Uplinks[0].Projects[0].ID, 0)
			},
			cleanupFunc: func() error {
				// set bandwidth limit back to initial value
				return planet.Satellites[0].DB.ProjectAccounting().UpdateProjectBandwidthLimit(ctx, planet.Uplinks[0].Projects[0].ID, memory.Size(*bandwidthLimit))
			},
		},
		{
			name:                  "GET prefix zip download list-only access",
			method:                "GET",
			path:                  path.Join("s", serializedListOnlyAccess, "testbucket", "test/?download=1"),
			status:                http.StatusForbidden,
			body:                  []string{"Access denied"},
			downloadPrefixEnabled: true,
		},
		{
			name:                  "GET prefix tar download list-only access",
			method:                "GET",
			path:                  path.Join("s", serializedListOnlyAccess, "testbucket", "test/?download=1&download-kind=tar.gz"),
			status:                http.StatusForbidden,
			body:                  []string{"Access denied"},
			downloadPrefixEnabled: true,
		},
		{
			name:                  "GET prefix zip download download-only access",
			method:                "GET",
			path:                  path.Join("s", serializedDownloadOnlyAccess, "testbucket", "test/?download=1"),
			status:                http.StatusForbidden,
			body:                  []string{"Access denied"},
			downloadPrefixEnabled: true,
			expectedRPCCalls:      slices.Repeat([]string{"/metainfo.Metainfo/CompressedBatch"}, 3),
		},
		{
			name:                  "GET prefix tar download download-only access",
			method:                "GET",
			path:                  path.Join("s", serializedDownloadOnlyAccess, "testbucket", "test/?download=1&download-kind=tar.gz"),
			status:                http.StatusForbidden,
			body:                  []string{"Access denied"},
			downloadPrefixEnabled: true,
			expectedRPCCalls:      slices.Repeat([]string{"/metainfo.Metainfo/CompressedBatch"}, 3),
		},
		{
			name:                  "GET nonexistent prefix zip download",
			method:                "GET",
			path:                  path.Join("s", serializedAccess, "testbucket", "test-empty/?download=1"),
			status:                http.StatusNotFound,
			body:                  []string{"Object not found"},
			downloadPrefixEnabled: true,
			expectedRPCCalls:      slices.Repeat([]string{"/metainfo.Metainfo/CompressedBatch"}, 3),
		},
		{
			name:                  "GET nonexistent prefix tar download",
			method:                "GET",
			path:                  path.Join("s", serializedAccess, "testbucket", "test-empty/?download=1&download-kind=tar.gz"),
			status:                http.StatusNotFound,
			body:                  []string{"Object not found"},
			downloadPrefixEnabled: true,
			expectedRPCCalls:      slices.Repeat([]string{"/metainfo.Metainfo/CompressedBatch"}, 3),
		},
		{
			name:                  "GET empty bucket zip download",
			method:                "GET",
			path:                  path.Join("s", serializedAccess, "emptytestbucket", "?download=1"),
			status:                http.StatusNotFound,
			body:                  []string{"Object not found"},
			downloadPrefixEnabled: true,
			expectedRPCCalls:      []string{"/metainfo.Metainfo/CompressedBatch"},
			prepFunc: func() error {
				return planet.Uplinks[0].CreateBucket(ctx, planet.Satellites[0], "emptytestbucket")
			},
		},
		{
			name:                  "GET empty bucket tar download",
			method:                "GET",
			path:                  path.Join("s", serializedAccess, "emptytestbucket", "?download=1&download-kind=tar.gz"),
			status:                http.StatusNotFound,
			body:                  []string{"Object not found"},
			downloadPrefixEnabled: true,
			expectedRPCCalls:      []string{"/metainfo.Metainfo/CompressedBatch"},
			cleanupFunc: func() error {
				return planet.Uplinks[0].DeleteBucket(ctx, planet.Satellites[0], "emptytestbucket")
			},
		},
		{
			name:                  "GET bad bucket zip download",
			method:                "GET",
			path:                  path.Join("s", serializedAccess, "badbucket", "?download=1"),
			status:                http.StatusNotFound,
			body:                  []string{"Bucket not found"},
			downloadPrefixEnabled: true,
			expectedRPCCalls:      []string{"/metainfo.Metainfo/CompressedBatch"},
		},
		{
			name:                  "GET bad bucket tar download",
			method:                "GET",
			path:                  path.Join("s", serializedAccess, "badbucket", "?download=1&download-kind=tar.gz"),
			status:                http.StatusNotFound,
			body:                  []string{"Bucket not found"},
			downloadPrefixEnabled: true,
			expectedRPCCalls:      []string{"/metainfo.Metainfo/CompressedBatch"},
		},
		{
			name:                  "GET prefix download bad download kind",
			method:                "GET",
			downloadPrefixEnabled: true,
			path:                  path.Join("s", serializedAccess, "testbucket", "?download=1&download-kind=notarealfiletype"),
			status:                http.StatusBadRequest,
		},
		{
			name:   "GET bucket zip download above limit",
			method: "GET",
			path:   path.Join("s", serializedAccess, "testbucket", "?download=1"),
			prepFunc: func() error {
				var eg errs.Group
				for i := 0; i < 3; i++ {
					eg.Add(planet.Uplinks[0].Upload(ctx, planet.Satellites[0], "testbucket", fmt.Sprintf("test/new%d", i), []byte("FOO")))
				}
				return eg.Err()
			},
			cleanupFunc: func() error {
				var eg errs.Group
				for i := 0; i < 3; i++ {
					eg.Add(planet.Uplinks[0].DeleteObject(ctx, planet.Satellites[0], "testbucket", fmt.Sprintf("test/new%d", i)))
				}
				return eg.Err()
			},
			status:                http.StatusOK,
			downloadPrefixEnabled: true,
			zipContent: map[string]string{
				"test/foo":         "FOOBAR",
				"test/new0":        "FOO",
				"test/new1":        "FOO",
				"test/new2":        "FOO",
				"pagination/test0": "FOOBAR",
				"pagination/test2": "FOOBAR",
				"TRUNCATED.txt": `This archive contains only the first 6 objects from the downloaded prefix.
To download a larger number of objects at once, download the prefix using the tar.gz archive.`,
			},
			expectedRPCCalls: slices.Repeat([]string{"/metainfo.Metainfo/CompressedBatch"}, 7),
		},
		{
			name:             "GET prefix download falls back to listing prefix if config disabled",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", "?download=1&download-kind=zip"),
			status:           http.StatusOK,
			body:             []string{"test/"},
			expectedRPCCalls: []string{"/metainfo.Metainfo/CompressedBatch" /* ListObjects */},
		},
	}

	mapper := objectmap.NewIPDB(&objectmap.MockReader{})

	callRecorder := rpctest.NewCallRecorder()
	contextWithRecording := rpcpool.WithDialerWrapper(ctx, func(ctx context.Context, dialer rpcpool.Dialer) rpcpool.Dialer {
		return func(ctx context.Context) (rpcpool.RawConn, *tls.ConnectionState, error) {
			conn, state, err := dialer(ctx)
			if err != nil {
				return conn, state, err
			}
			return callRecorder.Attach(conn), state, nil
		}
	})

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			callRecorder.Reset()

			if testCase.prepFunc != nil {
				ctx.Check(testCase.prepFunc)
			}
			if testCase.cleanupFunc != nil {
				defer ctx.Check(testCase.cleanupFunc)
			}

			host := testCase.host
			if host == "" {
				host = "localhost"
			}

			authConfig := authclient.Config{
				BaseURL: testCase.authserver,
				Token:   authToken,
			}

			dnsSrv, err := mockdns.NewServerWithLogger(testCase.dnsRecords, namedDebugStdLogger(t, zaptest.NewLogger(t), "mockdns"), false)
			require.NoError(t, err)
			defer ctx.Check(dnsSrv.Close)

			listPageLimit := 1
			if testCase.listPageLimit != nil {
				listPageLimit = testCase.listPageLimit.v
			}

			handler, err := sharing.NewHandler(zaptest.NewLogger(t), mapper, nil, nil, sharing.Config{
				Assets:                assets.FS(),
				URLBases:              []string{"http://localhost"},
				AuthServiceConfig:     authConfig,
				DNSServer:             dnsSrv.LocalAddr().String(),
				ListPageLimit:         listPageLimit,
				DownloadPrefixEnabled: testCase.downloadPrefixEnabled,
				DownloadZipLimit:      6,
			})
			require.Equal(t, testCase.newHandlerErr, err)
			if testCase.newHandlerErr != nil {
				return
			}

			url := "http://" + host + "/" + testCase.path
			w := httptest.NewRecorder()
			r, err := http.NewRequestWithContext(contextWithRecording, testCase.method, url, nil)
			require.NoError(t, err)

			for k, v := range testCase.reqHeader {
				r.Header.Set(k, v)
			}

			credsHandler := handler.CredentialsHandler(handler)
			credsHandler.ServeHTTP(w, r)

			assert.Equal(t, testCase.redirectLocation, w.Header().Get("Location"), "redirect location does not match")
			assert.Equal(t, testCase.status, w.Code, "status code does not match")
			if testCase.body != nil {
				for _, elem := range testCase.body {
					assert.Contains(t, w.Body.String(), elem, fmt.Sprintf("body does not contain expected element: %s", elem))
				}
			}
			if testCase.notContains != nil {
				for _, elem := range testCase.notContains {
					assert.NotContains(t, w.Body.String(), elem, fmt.Sprintf("body should not contain element: %s", elem))
				}
			}
			if testCase.zipContent != nil {
				zf, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
				require.NoError(t, err)

				assert.Len(t, zf.File, len(testCase.zipContent), fmt.Sprintf("zip file does not have expected number of entries. Testcase: %s", testCase.name))

				for name, expectedContent := range testCase.zipContent {
					f, err := zf.Open(name)
					require.NoError(t, err)
					defer func() { require.NoError(t, f.Close()) }()
					content, err := io.ReadAll(f)
					require.NoError(t, err)
					assert.Equal(t, expectedContent, string(content), fmt.Sprintf("zip entry does not have expected content: %s", expectedContent))
				}
			}
			if testCase.tarContent != nil {
				gzf, err := gzip.NewReader(bytes.NewReader(w.Body.Bytes()))
				require.NoError(t, err)
				defer func() { require.NoError(t, gzf.Close()) }()
				tf := tar.NewReader(gzf)

				downloaded := make(map[string]string)
				for {
					header, err := tf.Next()
					if err == io.EOF {
						break
					}
					require.NoError(t, err)

					name := header.Name
					data := make([]byte, header.Size)
					_, err = tf.Read(data)
					downloaded[name] = string(data)
					require.ErrorIs(t, err, io.EOF)
				}
				assert.EqualValues(t, len(downloaded), len(testCase.tarContent), fmt.Sprintf("tar file does not have expected number of entries. Testcase: %s", testCase.name))
				for name, expectedContent := range testCase.tarContent {
					require.Equal(t, expectedContent, downloaded[name], fmt.Sprintf("tar entry does not have expected content: %s", expectedContent))

				}
			}
			if testCase.expectedRPCCalls != nil {
				assert.ElementsMatch(t, testCase.expectedRPCCalls, callRecorder.History())
			}
		})
	}
}

func makeAuthHandler(t *testing.T, accessKeys []authHandlerEntry, token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.True(t, strings.HasPrefix(r.URL.Path, "/v1/access/"))
		require.Equal(t, r.Header.Get("Authorization"), "Bearer "+token)
		accessKey := strings.TrimPrefix(r.URL.Path, "/v1/access/")

		var entry authHandlerEntry
		for _, v := range accessKeys {
			if v.accessKey == accessKey {
				entry = v
				break
			}
		}

		if entry == (authHandlerEntry{}) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		require.NoError(t, json.NewEncoder(w).Encode(struct {
			AccessGrant     string `json:"access_grant"`
			PublicProjectID string `json:"public_project_id"`
			Public          bool   `json:"public"`
		}{
			AccessGrant:     entry.serializedAccess,
			PublicProjectID: entry.publicProjectID.String(),
			Public:          entry.public,
		}))
	})
}

func namedDebugStdLogger(t *testing.T, logger *zap.Logger, name string) *log.Logger {
	stdLogger, err := zap.NewStdLogAt(logger.Named(name), zapcore.DebugLevel)
	require.NoError(t, err)
	return stdLogger
}

func randomAccessKey(t *testing.T) string {
	key, err := authdb.NewEncryptionKey()
	require.NoError(t, err)

	return key.ToBase32()
}
