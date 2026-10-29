// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package linksharing_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"storj.io/common/testcontext"
	"storj.io/common/testrand"
	"storj.io/edge/pkg/linksharing/objectmap"
	"storj.io/edge/pkg/linksharing/sharing"
	"storj.io/edge/pkg/linksharing/sharing/assets"
	"storj.io/storj/private/testplanet"
)

// TestHeadOverHTTP2 checks that HEAD requests get the same headers as GET
// without a body over HTTP/2, which, unlike HTTP/1, fails body writes once a
// HEAD response's headers have been sent.
func TestHeadOverHTTP2(t *testing.T) {
	testplanet.Run(t, testplanet.Config{
		SatelliteCount:   1,
		StorageNodeCount: 1,
		UplinkCount:      1,
	}, func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet) {
		// enough objects for the listing page to exceed net/http's write buffer.
		for i := range 30 {
			require.NoError(t, planet.Uplinks[0].Upload(ctx, planet.Satellites[0], "testbucket", fmt.Sprintf("dir/file%02d.txt", i), testrand.BytesInt(100)))
		}
		require.NoError(t, planet.Uplinks[0].Upload(ctx, planet.Satellites[0], "testbucket", "page.txt", testrand.BytesInt(100)))

		access, err := planet.Uplinks[0].Access[planet.Satellites[0].ID()].Serialize()
		require.NoError(t, err)

		var h http.Handler
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
		srv.EnableHTTP2 = true
		srv.StartTLS()
		defer srv.Close()

		core, logs := observer.New(zap.DebugLevel)
		handler, err := sharing.NewHandler(zap.New(core), objectmap.NewIPDB(&objectmap.MockReader{}), nil, nil, sharing.Config{
			Assets:                assets.FS(),
			ListPageLimit:         100,
			URLBases:              []string{srv.URL},
			DownloadPrefixEnabled: true,
		})
		require.NoError(t, err)
		h = handler.CredentialsHandler(handler)

		base := srv.URL + "/" + path.Join("s", access, "testbucket")
		for _, url := range []string{
			base + "/dir/",
			base + "/page.txt",
			base + "/page.txt?wrap=1",
			base + "/page.txt?map=1",
			base + "/missing.txt",
			base + "/dir/?download=1&download-kind=zip",
			base + "/dir/?download=1&download-kind=tar.gz",
		} {
			get := do(ctx, t, srv.Client(), http.MethodGet, url)
			_, err := io.Copy(io.Discard, get.Body)
			require.NoError(t, err)
			require.NoError(t, get.Body.Close())
			require.Equal(t, 2, get.ProtoMajor)

			head := do(ctx, t, srv.Client(), http.MethodHead, url)
			body, err := io.ReadAll(head.Body)
			require.NoError(t, err)
			require.NoError(t, head.Body.Close())

			require.Equal(t, get.StatusCode, head.StatusCode, url)
			require.Equal(t, get.Header.Get("Content-Type"), head.Header.Get("Content-Type"), url)
			require.Equal(t, get.Header.Get("Content-Disposition"), head.Header.Get("Content-Disposition"), url)
			require.Empty(t, body, url)
		}

		errors := logs.Filter(func(e observer.LoggedEntry) bool { return e.Level >= zap.ErrorLevel })
		require.Zero(t, errors.Len(), "errors: %v", errors.AllUntimed())
	})
}

func do(ctx context.Context, t *testing.T, client *http.Client, method, url string) *http.Response {
	r, err := http.NewRequestWithContext(ctx, method, url, nil)
	require.NoError(t, err)
	resp, err := client.Do(r)
	require.NoError(t, err)
	return resp
}
