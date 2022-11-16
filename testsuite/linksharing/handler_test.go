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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

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
	}, testHandlerRequests)
}

type authHandlerEntry struct {
	grant  string
	public bool
}

func testHandlerRequests(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet) {
	err := planet.Uplinks[0].Upload(ctx, planet.Satellites[0], "testbucket", "test/foo", []byte("FOO"))
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

	authToken := hex.EncodeToString(testrand.BytesInt(16))
	validAuthServer := httptest.NewServer(makeAuthHandler(t, map[string]authHandlerEntry{
		"GOODACCESS":     {serializedAccess, true},
		"PRIVATEACCESS":  {serializedAccess, false},
		"LISTONLYACCESS": {serializedListOnlyAccess, true},
	}, authToken))
	defer validAuthServer.Close()

	testCases := []struct {
		name             string
		method           string
		path             string
		status           int
		body             string
		authserver       string
		expectedRPCCalls []string
		prepFunc         func() error
	}{
		{
			name:   "invalid method",
			method: "PUT",
			status: http.StatusMethodNotAllowed,
			body:   "Malformed request.",
		},
		{
			name:   "GET missing access",
			method: "GET",
			path:   "s/",
			status: http.StatusBadRequest,
			body:   "Malformed request.",
		},
		{
			name:       "GET misconfigured auth server",
			method:     "GET",
			path:       path.Join("s", "ACCESS", "testbucket", "test/foo"),
			status:     http.StatusInternalServerError,
			body:       "Internal server error.",
			authserver: "invalid://",
		},
		{
			name:       "GET missing access key",
			method:     "GET",
			path:       path.Join("s", "MISSINGACCESS", "testbucket", "test/foo"),
			status:     http.StatusNotFound,
			body:       "Not found.",
			authserver: validAuthServer.URL,
		},
		{
			name:       "GET private access key",
			method:     "GET",
			path:       path.Join("s", "PRIVATEACCESS", "testbucket", "test/foo"),
			status:     http.StatusForbidden,
			body:       "Access denied.",
			authserver: validAuthServer.URL,
		},
		{
			name:       "GET found access key",
			method:     "GET",
			path:       path.Join("s", "GOODACCESS", "testbucket", "test/foo"),
			status:     http.StatusOK,
			body:       "foo",
			authserver: validAuthServer.URL,
		},
		{
			name:   "GET missing bucket",
			method: "GET",
			path:   path.Join("s", serializedAccess),
			status: http.StatusBadRequest,
			body:   "Malformed request.",
		},
		{
			name:   "GET object not found",
			method: "GET",
			path:   path.Join("s", serializedAccess, "testbucket", "test/bar"),
			status: http.StatusNotFound,
			body:   "Object not found",
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
			name:             "GET download with list-only access grant",
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
			name:       "HEAD misconfigured auth server",
			method:     "HEAD",
			path:       path.Join("s", "ACCESS", "testbucket", "test/foo"),
			status:     http.StatusInternalServerError,
			body:       "Internal server error.",
			authserver: "invalid://",
		},
		{
			name:       "HEAD missing access key",
			method:     "HEAD",
			path:       path.Join("s", "MISSINGACCESS", "testbucket", "test/foo"),
			status:     http.StatusNotFound,
			body:       "Not found.",
			authserver: validAuthServer.URL,
		},
		{
			name:       "HEAD private access key",
			method:     "GET",
			path:       path.Join("s", "PRIVATEACCESS", "testbucket", "test/foo"),
			status:     http.StatusForbidden,
			body:       "Access denied",
			authserver: validAuthServer.URL,
		},
		{
			name:       "HEAD found access key",
			method:     "GET",
			path:       path.Join("s", "GOODACCESS", "testbucket", "test/foo"),
			status:     http.StatusOK,
			body:       "",
			authserver: validAuthServer.URL,
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
				err := testCase.prepFunc()
				require.NoError(t, err)
			}

			handler, err := sharing.NewHandler(zaptest.NewLogger(t), mapper, nil, nil, sharing.Config{
				URLBases:  []string{"http://localhost"},
				Templates: "./../../pkg/linksharing/web/",
				AuthServiceConfig: authclient.Config{
					BaseURL: testCase.authserver,
					Token:   authToken,
				},
			})
			require.NoError(t, err)

			url := "http://localhost/" + testCase.path
			w := httptest.NewRecorder()
			r, err := http.NewRequestWithContext(contextWithRecording, testCase.method, url, nil)
			require.NoError(t, err)
			handler.ServeHTTP(w, r)

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
			w.WriteHeader(http.StatusNotFound)
		}
	})
}
