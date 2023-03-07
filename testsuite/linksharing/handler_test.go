// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package linksharing_test

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/memory"
	"storj.io/common/rpc/rpcpool"
	"storj.io/common/rpc/rpctest"
	"storj.io/common/testcontext"
	"storj.io/common/testrand"
	"storj.io/drpc"
	"storj.io/gateway-mt/pkg/authclient"
	"storj.io/gateway-mt/pkg/linksharing/objectmap"
	"storj.io/gateway-mt/pkg/linksharing/sharing"
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
				URLBases: []string{"gopher://chunks"},
			},
			err: "URL base must be http:// or https://",
		},
		{
			name: "URL base must contain host",
			config: sharing.Config{
				URLBases: []string{"http://"},
			},
			err: "URL base must contain host",
		},
		{
			name: "URL base can have a port",
			config: sharing.Config{
				URLBases: []string{"http://host:99"},
			},
		},
		{
			name: "URL base can have a path",
			config: sharing.Config{
				URLBases: []string{"http://host/gopher"},
			},
		},
		{
			name: "URL base must not contain user info",
			config: sharing.Config{
				URLBases: []string{"http://joe@host"},
			},
			err: "URL base must not contain user info",
		},
		{
			name: "URL base must not contain query values",
			config: sharing.Config{
				URLBases: []string{"http://host/?gopher=chunks"},
			},
			err: "URL base must not contain query values",
		},
		{
			name: "URL base must not contain a fragment",
			config: sharing.Config{
				URLBases: []string{"http://host/#gopher-chunks"},
			},
			err: "URL base must not contain a fragment",
		},
	}

	mapper := objectmap.NewIPDB(&objectmap.MockReader{})

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			testCase.config.Templates = "./../../pkg/linksharing/web"
			handler, err := sharing.NewHandler(zaptest.NewLogger(t), mapper, nil, nil, nil, testCase.config)
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
	}, testHandlerRequests)
}

type authHandlerEntry struct {
	grant  string
	public bool
}

func testHandlerRequests(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet) {
	err := planet.Uplinks[0].Upload(ctx, planet.Satellites[0], "testbucket", "test/foo", []byte("FOO"))
	require.NoError(t, err)

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

	downloadOnlyAccess, err := access.Share(
		uplink.Permission{AllowList: false, AllowDownload: true},
		uplink.SharePrefix{Bucket: "testbucket"},
	)
	require.NoError(t, err)

	serializedDownloadOnlyAccess, err := downloadOnlyAccess.Serialize()
	require.NoError(t, err)

	missingAccessName := "jwaohtj3dhixxfpzhwj522x7z3pm"
	goodAccessName := "jwaohtj3dhixxfpzhwj522x7z3pg"
	privateAccessName := "jwaohtj3dhixxfpzhwj522x7z3pp"
	listOnlyAccessName := "jwaohtj3dhixxfpzhwj522x7z3pl"
	downloadOnlyAccessName := "jwaohtj3dhixxfpzhwj522x7z3pd"

	authToken := hex.EncodeToString(testrand.BytesInt(16))
	validAuthServer := httptest.NewServer(makeAuthHandler(t, map[string]authHandlerEntry{
		goodAccessName:         {serializedAccess, true},
		privateAccessName:      {serializedAccess, false},
		listOnlyAccessName:     {serializedListOnlyAccess, true},
		downloadOnlyAccessName: {serializedDownloadOnlyAccess, true},
	}, authToken))
	defer validAuthServer.Close()

	testCases := []struct {
		name             string
		host             string
		method           string
		path             string
		txtRecords       map[string][]string
		redirectLocation string
		status           int
		body             string
		authserver       string
		expectedRPCCalls []string
		prepFunc         func() error
		cleanupFunc      func() error
	}{
		{
			name:             "invalid method",
			method:           "PUT",
			status:           http.StatusMethodNotAllowed,
			body:             "Malformed request.",
			expectedRPCCalls: []string{},
		},
		{
			name:             "GET missing access",
			method:           "GET",
			path:             "s/",
			status:           http.StatusBadRequest,
			body:             "Malformed request.",
			expectedRPCCalls: []string{},
		},
		{
			name:             "GET misconfigured auth server",
			method:           "GET",
			path:             path.Join("s", goodAccessName, "testbucket", "test/foo"),
			status:           http.StatusInternalServerError,
			body:             "Internal server error.",
			authserver:       "invalid://",
			expectedRPCCalls: []string{},
		},
		{
			name:             "GET missing access key",
			method:           "GET",
			path:             path.Join("s", missingAccessName, "testbucket", "test/foo"),
			status:           http.StatusUnauthorized,
			body:             "Access denied.",
			authserver:       validAuthServer.URL,
			expectedRPCCalls: []string{},
		},
		{
			name:             "GET private access key",
			method:           "GET",
			path:             path.Join("s", privateAccessName, "testbucket", "test/foo"),
			status:           http.StatusForbidden,
			body:             "Access denied.",
			authserver:       validAuthServer.URL,
			expectedRPCCalls: []string{},
		},
		{
			name:             "GET found access key",
			method:           "GET",
			path:             path.Join("s", goodAccessName, "testbucket", "test/foo"),
			status:           http.StatusOK,
			body:             "foo",
			authserver:       validAuthServer.URL,
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/GetObjectIPs"},
		},
		{
			name:             "GET missing bucket",
			method:           "GET",
			path:             path.Join("s", serializedAccess),
			status:           http.StatusBadRequest,
			body:             "Malformed request.",
			expectedRPCCalls: []string{},
		},
		{
			name:             "GET object not found",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", "test/bar"),
			status:           http.StatusNotFound,
			body:             "Object not found",
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/ListObjects"},
		},
		{
			name:             "GET success",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", "test/foo"),
			status:           http.StatusOK,
			body:             "foo",
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/GetObjectIPs"},
		},
		{
			name:             "GET download success",
			method:           "GET",
			path:             path.Join("raw", serializedAccess, "testbucket", "test/foo"),
			status:           http.StatusOK,
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/DownloadObject"},
		},
		{
			name:       "GET download with trailing slash",
			method:     "GET",
			path:       path.Join("raw", goodAccessName, "testbucket", "test/foo1") + "/",
			status:     http.StatusOK,
			body:       "FOO",
			authserver: validAuthServer.URL,
			// todo(sean): sometimes this responds with different results. For example:
			// * []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/DownloadObject"}
			// * []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/DownloadObject", "/metainfo.Metainfo/GetObject"}
			//
			// expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/DownloadObject"},
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
			body:             "test/",
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/ListObjects"},
		},
		{
			name:             "GET prefix listing success",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", "test") + "/",
			status:           http.StatusOK,
			body:             "foo",
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/ListObjects"},
		},
		{
			name:             "GET prefix listing empty",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", "test-empty") + "/",
			status:           http.StatusNotFound,
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/ListObjects"},
		},
		{
			name:             "GET prefix redirect",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", "test"),
			status:           http.StatusSeeOther,
			redirectLocation: "/" + path.Join("s", serializedAccess, "testbucket", "test") + "/",
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/ListObjects"},
		},
		{
			name:             "GET list-only access grant",
			method:           "GET",
			path:             path.Join("s", serializedListOnlyAccess, "testbucket", "test/foo"),
			status:           http.StatusOK,
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/GetObjectIPs"},
		},
		{
			name:             "GET download list-only access grant",
			method:           "GET",
			path:             path.Join("raw", serializedListOnlyAccess, "testbucket", "test/foo"),
			status:           http.StatusForbidden,
			body:             "Access denied",
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/DownloadObject"},
		},
		{
			name:             "HEAD missing access",
			method:           "HEAD",
			path:             "s/",
			status:           http.StatusBadRequest,
			body:             "Malformed request.",
			expectedRPCCalls: []string{},
		},
		{
			name:             "HEAD misconfigured auth server",
			method:           "HEAD",
			path:             path.Join("s", goodAccessName, "testbucket", "test/foo"),
			status:           http.StatusInternalServerError,
			body:             "Internal server error.",
			authserver:       "invalid://",
			expectedRPCCalls: []string{},
		},
		{
			name:             "HEAD missing access key",
			method:           "HEAD",
			path:             path.Join("s", missingAccessName, "testbucket", "test/foo"),
			status:           http.StatusUnauthorized,
			body:             "Access denied.",
			authserver:       validAuthServer.URL,
			expectedRPCCalls: []string{},
		},
		{
			name:             "HEAD private access key",
			method:           "GET",
			path:             path.Join("s", privateAccessName, "testbucket", "test/foo"),
			status:           http.StatusForbidden,
			body:             "Access denied",
			authserver:       validAuthServer.URL,
			expectedRPCCalls: []string{},
		},
		{
			name:             "HEAD found access key",
			method:           "GET",
			path:             path.Join("s", goodAccessName, "testbucket", "test/foo"),
			status:           http.StatusOK,
			body:             "",
			authserver:       validAuthServer.URL,
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/GetObjectIPs"},
		},
		{
			name:             "HEAD missing bucket",
			method:           "HEAD",
			path:             path.Join("s", serializedAccess),
			status:           http.StatusBadRequest,
			body:             "Malformed request.",
			expectedRPCCalls: []string{},
		},
		{
			name:             "HEAD object not found",
			method:           "HEAD",
			path:             path.Join("s", serializedAccess, "testbucket", "test/bar"),
			status:           http.StatusNotFound,
			body:             "Object not found",
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/ListObjects"},
		},
		{
			name:             "HEAD success",
			method:           "HEAD",
			path:             path.Join("s", serializedAccess, "testbucket", "test/foo"),
			status:           http.StatusOK,
			body:             "",
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/GetObjectIPs"},
		},
		{
			name:             "GET download when exceeded bandwidth limit",
			method:           "GET",
			path:             path.Join("raw", serializedAccess, "testbucket", "test/foo"),
			status:           http.StatusTooManyRequests,
			body:             "Bandwidth limit exceeded",
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/DownloadObject"},
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
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/ListObjects"},
		},
		{
			name:             "GET prefix containing index.html",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", "test/bar") + "/",
			status:           http.StatusOK,
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/GetObjectIPs"},
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
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/GetObjectIPs"},
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
			body:             "Malformed request.",
			authserver:       validAuthServer.URL,
			expectedRPCCalls: []string{},
		},
		{
			name:   "hosting GET empty access TXT record",
			host:   "mydomain.com",
			method: "GET",
			txtRecords: map[string][]string{
				"txt-mydomain.com.": {
					"storj-root:testbucket",
				},
			},
			status:           http.StatusBadRequest,
			body:             "Malformed request.",
			authserver:       validAuthServer.URL,
			expectedRPCCalls: []string{},
		},
		{
			name:   "hosting GET empty root TXT record",
			host:   "mydomain.com",
			method: "GET",
			txtRecords: map[string][]string{
				"txt-mydomain.com.": {
					"storj-access:" + goodAccessName,
				},
			},
			status:           http.StatusBadRequest,
			body:             "Invalid bucket name.",
			authserver:       validAuthServer.URL,
			expectedRPCCalls: []string{},
		},
		{
			name:   "hosting GET private access key",
			host:   "mydomain.com",
			method: "GET",
			txtRecords: map[string][]string{
				"txt-mydomain.com.": {
					"storj-access:" + privateAccessName,
					"storj-root:testbucket",
				},
			},
			status:           http.StatusForbidden,
			body:             "Access denied.",
			authserver:       validAuthServer.URL,
			expectedRPCCalls: []string{},
		},
		{
			name:   "hosting GET download list-only access",
			host:   "mydomain.com",
			method: "GET",
			txtRecords: map[string][]string{
				"txt-mydomain.com.": {
					"storj-access:" + serializedListOnlyAccess,
					"storj-root:testbucket/test/foo",
				},
			},
			status:           http.StatusForbidden,
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/ListObjects", "/metainfo.Metainfo/DownloadObject"},
		},
		{
			name:   "hosting GET prefix download-only access",
			host:   "mydomain.com",
			method: "GET",
			path:   "test/foo/",
			txtRecords: map[string][]string{
				"txt-mydomain.com.": {
					"storj-access:" + downloadOnlyAccessName,
					"storj-root:testbucket",
				},
			},
			status:           http.StatusForbidden,
			authserver:       validAuthServer.URL,
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/ListObjects"},
		},
		{
			name:   "hosting GET root index.html download-only access",
			host:   "mydomain.com",
			method: "GET",
			txtRecords: map[string][]string{
				"txt-mydomain.com.": {
					"storj-access:" + downloadOnlyAccessName,
					"storj-root:testbucket",
				},
			},
			status:           http.StatusOK,
			body:             "HELLO!",
			authserver:       validAuthServer.URL,
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/DownloadObject"},
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
			txtRecords: map[string][]string{
				"txt-mydomain.com.": {
					"storj-access:" + goodAccessName,
					"storj-root:testbucket",
				},
			},
			status:           http.StatusOK,
			body:             "HELLO!",
			authserver:       validAuthServer.URL,
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/DownloadObject"},
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
			txtRecords: map[string][]string{
				"txt-mydomain.com.": {
					"storj-access:" + serializedAccess,
					"storj-root:testbucket/prefix",
				},
			},
			status:           http.StatusOK,
			body:             "HELLO!",
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/DownloadObject"},
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
			txtRecords: map[string][]string{
				"txt-mydomain.com.": {
					"storj-access:" + goodAccessName,
					"storj-root:testbucket/test",
				},
			},
			status:           http.StatusOK,
			body:             "FOO",
			authserver:       validAuthServer.URL,
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/DownloadObject"},
		},
		{
			name:   "hosting GET root 404 default page",
			host:   "mydomain.com",
			method: "GET",
			path:   "/doesnotexist",
			txtRecords: map[string][]string{
				"txt-mydomain.com.": {
					"storj-access:" + goodAccessName,
					"storj-root:testbucket",
				},
			},
			status:           http.StatusNotFound,
			body:             "Object not found",
			authserver:       validAuthServer.URL,
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/ListObjects", "/metainfo.Metainfo/DownloadObject"},
		},
		{
			name:   "hosting GET root 404.html",
			host:   "mydomain.com",
			method: "GET",
			path:   "/doesnotexist",
			txtRecords: map[string][]string{
				"txt-mydomain.com.": {
					"storj-access:" + goodAccessName,
					"storj-root:testbucket",
				},
			},
			status:           http.StatusNotFound,
			body:             "NOT FOUND!",
			authserver:       validAuthServer.URL,
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/ListObjects", "/metainfo.Metainfo/DownloadObject"},
			prepFunc: func() error {
				return planet.Uplinks[0].Upload(ctx, planet.Satellites[0], "testbucket", "404.html", []byte("NOT FOUND!"))
			},
			cleanupFunc: func() error {
				return planet.Uplinks[0].DeleteObject(ctx, planet.Satellites[0], "testbucket", "404.html")
			},
		},
	}

	mapper := objectmap.NewIPDB(&objectmap.MockReader{})

	callRecorder := rpctest.NewCallRecorder()
	contextWithRecording := rpcpool.WithDialerWrapper(ctx, func(ctx context.Context, dialer rpcpool.Dialer) rpcpool.Dialer {
		return func(ctx context.Context) (drpc.Conn, *tls.ConnectionState, error) {
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

			txtRecords := sharing.NewTXTRecords(time.Second, &mockDNS{
				txtRecords: testCase.txtRecords,
			}, authclient.New(authConfig))

			handler, err := sharing.NewHandler(zaptest.NewLogger(t), mapper, txtRecords, nil, nil, sharing.Config{
				URLBases:          []string{"http://localhost"},
				Templates:         "./../../pkg/linksharing/web/",
				AuthServiceConfig: authConfig,
			})
			require.NoError(t, err)

			url := "http://" + host + "/" + testCase.path
			w := httptest.NewRecorder()
			r, err := http.NewRequestWithContext(contextWithRecording, testCase.method, url, nil)
			require.NoError(t, err)
			handler.ServeHTTP(w, r)

			assert.Equal(t, testCase.redirectLocation, w.Header().Get("Location"), "redirect location does not match")
			assert.Equal(t, testCase.status, w.Code, "status code does not match")
			assert.Contains(t, w.Body.String(), testCase.body, "body does not match")
			if testCase.expectedRPCCalls != nil {
				assert.Equal(t, testCase.expectedRPCCalls, callRecorder.History())
			}
		})
	}
}

func makeAuthHandler(t *testing.T, accessKeys map[string]authHandlerEntry, token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.True(t, strings.HasPrefix(r.URL.Path, "/v1/access/"))
		require.Equal(t, r.Header.Get("Authorization"), "Bearer "+token)
		accessKey := strings.TrimPrefix(r.URL.Path, "/v1/access/")
		if grant, ok := accessKeys[accessKey]; ok {
			require.NoError(t, json.NewEncoder(w).Encode(struct {
				AccessGrant string `json:"access_grant"`
				Public      bool   `json:"public"`
			}{
				AccessGrant: grant.grant,
				Public:      grant.public,
			}))
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	})
}

type mockDNS struct {
	txtRecords map[string][]string
}

func (d *mockDNS) Lookup(ctx context.Context, host string, recordType uint16) (_ *dns.Msg, err error) {
	var r []dns.RR
	for name, records := range d.txtRecords {
		r = append(r, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:     name,
				Rrtype:   0x10,
				Class:    0x1,
				Ttl:      0x111,
				Rdlength: 0x1c,
			},
			Txt: records,
		})
	}
	return &dns.Msg{
		Answer: r,
	}, nil
}
