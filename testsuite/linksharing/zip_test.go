// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package linksharing_test

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/rpc/rpcpool"
	"storj.io/common/rpc/rpctest"
	"storj.io/common/testcontext"
	"storj.io/drpc"
	"storj.io/gateway-mt/pkg/linksharing/objectmap"
	"storj.io/gateway-mt/pkg/linksharing/sharing"
	"storj.io/storj/private/testplanet"
)

// CreateZip returns the bytes of a ZIP file which contains one stored file and one deflate file.
func CreateZip(t *testing.T) []byte {
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)

	f, err := w.Create("deflate.txt")
	require.NoError(t, err)
	_, err = f.Write([]byte("Saved as deflate"))
	require.NoError(t, err)

	f, err = w.CreateHeader(&zip.FileHeader{Name: "store.txt", Method: zip.Store})
	require.NoError(t, err)
	_, err = f.Write([]byte("Saved as store"))
	require.NoError(t, err)

	require.NoError(t, w.Flush())
	require.NoError(t, w.Close())

	return buf.Bytes()
}

// TestZipRequests tests ZIP archive listing, file download (including GZIP), file wrapping, and file mapping.
func TestZipRequests(t *testing.T) {
	testplanet.Run(t, testplanet.Config{SatelliteCount: 1, StorageNodeCount: 1, UplinkCount: 1}, testZipRequests)
}

func testZipRequests(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet) {
	// add zip file
	err := planet.Uplinks[0].Upload(ctx, planet.Satellites[0], "testbucket", "test.zip", CreateZip(t))
	require.NoError(t, err)

	access := planet.Uplinks[0].Access[planet.Satellites[0].ID()]
	serializedAccess, err := access.Serialize()
	require.NoError(t, err)

	testCases := []struct {
		name             string
		method           string
		path             string
		archivePath      string
		status           int
		body             string
		expectedRPCCalls []string
		acceptGzip       bool
		expectGzip       bool
		prepFunc         func() error
	}{
		{
			name:             "ZIP wrap",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", "test.zip"),
			archivePath:      "/",
			status:           http.StatusOK,
			body:             "View Contents",
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/GetObjectIPs"},
		},
		{
			name:             "ZIP list",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", "test.zip") + "?path=/",
			archivePath:      "/",
			status:           http.StatusOK,
			body:             "Back",
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/DownloadObject"},
		},
		{
			name:             "ZIP download store.txt",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", "test.zip") + "?path=store.txt&download=1",
			status:           http.StatusOK,
			body:             "Saved as store",
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/DownloadObject"},
		},
		{
			name:             "ZIP download deflate.txt",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", "test.zip") + "?path=deflate.txt&download=1",
			status:           http.StatusOK,
			body:             "Saved as deflate",
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/DownloadObject"},
		},
		{
			name:             "ZIP download store.txt client supports gzip",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", "test.zip") + "?path=store.txt&download=1",
			status:           http.StatusOK,
			body:             "Saved as store",
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/DownloadObject"},
			acceptGzip:       true,
		},
		{
			name:             "ZIP download deflate.txt client supports gzip",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", "test.zip") + "?path=deflate.txt&download=1",
			status:           http.StatusOK,
			body:             "Saved as deflate",
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/DownloadObject"},
			acceptGzip:       true,
			expectGzip:       true,
		},
		{
			name:             "ZIP wrap store.txt",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", "test.zip") + "?path=store.txt&wrap=1",
			status:           http.StatusOK,
			body:             "14 B", // the wrapper page shows the file size
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/GetObjectIPs", "/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/DownloadObject"},
		},
		{
			name:             "ZIP wrap deflate.txt",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", "test.zip") + "?path=deflate.txt&wrap=1",
			status:           http.StatusOK,
			body:             "16 B", // the wrapper page shows the file size
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/GetObjectIPs", "/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/DownloadObject"},
		},
		{
			name:             "ZIP map store.txt",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", "test.zip") + "?path=store.txt&map=1",
			status:           http.StatusOK,
			body:             "Files under 4k are stored as metadata with strong encryption.",
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/GetObjectIPs"},
		},
		{
			name:             "ZIP map deflate.txt",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", "test.zip") + "?path=deflate.txt&map=1",
			status:           http.StatusOK,
			body:             "Files under 4k are stored as metadata with strong encryption.",
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/GetObjectIPs"},
		},
		{
			name:             "ZIP list when exceeded bandwidth limit",
			method:           "GET",
			path:             path.Join("s", serializedAccess, "testbucket", "test.zip") + "?path=/",
			archivePath:      "/",
			status:           http.StatusTooManyRequests,
			body:             "Bandwidth limit exceeded",
			expectedRPCCalls: []string{"/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/GetObject", "/metainfo.Metainfo/DownloadObject"},
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
			})
			require.NoError(t, err)

			url := "http://localhost/" + testCase.path
			w := httptest.NewRecorder()
			r, err := http.NewRequestWithContext(contextWithRecording, testCase.method, url, nil)
			if testCase.acceptGzip {
				r.Header.Add("Accept-Encoding", "gzip")
			}
			require.NoError(t, err)
			handler.ServeHTTP(w, r)
			// check status
			assert.Equal(t, testCase.status, w.Code, "status code does not match")
			// check content encoding
			var body []byte
			responseIsGzip := len(w.Header()["Content-Encoding"]) > 0 && w.Header()["Content-Encoding"][0] == "gzip"
			require.Equal(t, responseIsGzip, testCase.expectGzip)
			// check body content (including gzip)
			if responseIsGzip {
				readerCloser, err := gzip.NewReader(w.Body)
				require.NoError(t, err)
				defer ctx.Check(readerCloser.Close)
				body, err = io.ReadAll(readerCloser)
				require.NoError(t, err)
			} else {
				body, err = io.ReadAll(w.Body)
				require.NoError(t, err)
			}
			assert.Contains(t, string(body), testCase.body, "body does not match")
			// check RPC calls
			assert.Equal(t, testCase.expectedRPCCalls, callRecorder.History())
		})
	}
}
