// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package linksharing_test

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/foxcpp/go-mockdns"
	"github.com/letsencrypt/pebble/v2/ca"
	"github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/va"
	"github.com/letsencrypt/pebble/v2/wfe"
	"github.com/stretchr/testify/require"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"golang.org/x/sync/errgroup"

	"storj.io/common/grant"
	"storj.io/common/identity"
	"storj.io/common/identity/testidentity"
	"storj.io/common/macaroon"
	"storj.io/common/peertls"
	"storj.io/common/pkcrypto"
	"storj.io/common/storj"
	"storj.io/common/testcontext"
	"storj.io/common/testrand"
	"storj.io/edge/pkg/authclient"
	"storj.io/edge/pkg/gcslock/gcsops"
	"storj.io/edge/pkg/httpserver"
	"storj.io/edge/pkg/linksharing"
	"storj.io/edge/pkg/linksharing/sharing"
	"storj.io/edge/pkg/linksharing/sharing/assets"
	"storj.io/edge/pkg/tierquery"
	"storj.io/storj/private/testplanet"
	"storj.io/storj/satellite"
	"storj.io/storj/satellite/console"
	"storj.io/uplink"
)

func TestIntegration(t *testing.T) {
	t.Parallel()

	gcsKeyPath, gcsBucketName, err := findCredentials()
	if err != nil {
		t.Skipf("Skipping %s without credentials/bucket provided", t.Name())
	}

	tests := []struct {
		name               string
		tlsRecord          bool
		cnameRecord        string
		dialContext        func(peer *linksharing.Peer) func(ctx context.Context, network, addr string) (net.Conn, error)
		reconfigure        func(config *linksharing.Config)
		prepare            func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet, root string)
		url                func(t *testing.T, peer *linksharing.Peer, accessKey, root, publicDomain, customDomain string) string
		test               func(t *testing.T, ctx *testcontext.Context, peer *linksharing.Peer, accesses []authHandlerEntry, publicDomain, customDomain string, client http.Client)
		method             string
		expectedStatusCode int
		expectedBody       string
		expectedHeaders    map[string]string
		followRedirect     bool
		wantRedirectResp   bool
		redirectLocation   func(t *testing.T, peer *linksharing.Peer, accessKey, root, publicDomain, customDomain string) string
		redirectStatusCode int
		wantErr            bool
	}{
		{
			name: "Method not allowed",
			url: func(t *testing.T, peer *linksharing.Peer, _, _, publicDomain, _ string) string {
				return fmt.Sprintf("https://%s", lookupHost(t, publicDomain, peer.Server.AddrTLS()))
			},
			method:             http.MethodPost,
			expectedStatusCode: http.StatusMethodNotAllowed,
			expectedBody:       "Method Not Allowed",
		},
		{
			name: "CORS headers",
			url: func(t *testing.T, peer *linksharing.Peer, _, _, publicDomain, _ string) string {
				return fmt.Sprintf("https://%s", lookupHost(t, publicDomain, peer.Server.AddrTLS()))
			},
			method: http.MethodOptions,
			expectedHeaders: map[string]string{
				"Access-Control-Allow-Origin":  "*",
				"Access-Control-Allow-Methods": "GET, HEAD",
				"Access-Control-Allow-Headers": "*",
			},
		},
		{
			name: "Public health and static endpoints",
			reconfigure: func(config *linksharing.Config) {
				config.ConcurrentRequestLimit = 1
				config.ShutdownDelay = 5 * time.Second
			},
			test: func(t *testing.T, ctx *testcontext.Context, peer *linksharing.Peer, accesses []authHandlerEntry, publicDomain, _ string, client http.Client) {
				healthURL := fmt.Sprintf("https://%s/health/process", lookupHost(t, publicDomain, peer.Server.AddrTLS()))
				staticURL := fmt.Sprintf("https://%s/static/img/logo.svg", lookupHost(t, publicDomain, peer.Server.AddrTLS()))

				var group errgroup.Group

				// test health and static endpoints aren't rate limited.
				for i := range 20 {
					url := healthURL
					if i%2 == 0 {
						url = staticURL
					}

					req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
					require.NoError(t, err)

					group.Go(func() error {
						resp, err := client.Do(req) //nolint:bodyclose
						if err != nil {
							return err
						}
						ctx.Check(resp.Body.Close)
						if resp.StatusCode != http.StatusOK {
							return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
						}
						return nil
					})
				}
				require.NoError(t, group.Wait())

				ctx.Go(peer.Close)

				req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
				require.NoError(t, err)

				resp, err := client.Do(req) //nolint:bodyclose
				require.NoError(t, err)
				ctx.Check(resp.Body.Close)

				require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
			},
		},
		{
			name: "Limit applied to normal requests",
			reconfigure: func(config *linksharing.Config) {
				config.ConcurrentRequestLimit = 5
			},
			prepare: func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet, _ string) {
				for i := range planet.Uplinks {
					planet.Uplinks[i].Access[planet.Satellites[0].NodeURL().ID] = newPaidAccess(ctx, t, planet.Satellites[0])
					require.NoError(t, planet.Uplinks[i].Upload(ctx, planet.Satellites[0], "test", "index.html", []byte("HELLO!")))
				}
			},
			test: func(t *testing.T, ctx *testcontext.Context, peer *linksharing.Peer, accesses []authHandlerEntry, publicDomain, _ string, client http.Client) {
				if len(accesses) != 2 {
					t.Fatal("misconfigured test")
				}

				url1 := fmt.Sprintf("https://%s/raw/%s/test/index.html", lookupHost(t, publicDomain, peer.Server.AddrTLS()), accesses[0].accessKey)
				url2 := fmt.Sprintf("https://%s/raw/%s/test/index.html", lookupHost(t, publicDomain, peer.Server.AddrTLS()), accesses[1].accessKey)

				var group errgroup.Group

				doReq := func(url string, index int, responses []int) error {
					req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
					require.NoError(t, err)

					resp, err := client.Do(req) //nolint:bodyclose
					if err != nil {
						return err
					}
					ctx.Check(resp.Body.Close)
					switch resp.StatusCode {
					case http.StatusOK, http.StatusTooManyRequests:
						responses[index] = resp.StatusCode
						return nil
					default:
						return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
					}
				}

				url1RequestCount := 10
				url2RequestCount := 2

				url1Responses := make([]int, url1RequestCount)
				url2Responses := make([]int, url2RequestCount)

				for i := range url1RequestCount {
					i := i
					group.Go(func() error {
						return doReq(url1, i, url1Responses)
					})
				}
				for i := range url2RequestCount {
					i := i
					group.Go(func() error {
						return doReq(url2, i, url2Responses)
					})
				}
				require.NoError(t, group.Wait())

				countLimitResponses := func(responses []int) int {
					var limited int
					for _, statusCode := range responses {
						if statusCode == http.StatusTooManyRequests {
							limited++
						}
					}
					return limited
				}

				require.Greater(t, countLimitResponses(url1Responses), 0)
				require.Equal(t, 0, countLimitResponses(url2Responses))
			},
		},
		{
			name:      "Health endpoint not applied to custom domain",
			tlsRecord: true,
			prepare: func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet, root string) {
				planet.Uplinks[0].Access[planet.Satellites[0].NodeURL().ID] = newPaidAccess(ctx, t, planet.Satellites[0])
				require.NoError(t, planet.Uplinks[0].Upload(ctx, planet.Satellites[0], root, "health/process", []byte("HELLO!")))
			},
			url: func(t *testing.T, peer *linksharing.Peer, _, _, _, customDomain string) string {
				return fmt.Sprintf("https://%s/health/process", lookupHost(t, customDomain, peer.Server.AddrTLS()))
			},
		},
		{
			name: "Static endpoint public domain",
			url: func(t *testing.T, peer *linksharing.Peer, _, _, publicDomain, _ string) string {
				return fmt.Sprintf("https://%s/static/img/logo.svg", lookupHost(t, publicDomain, peer.Server.AddrTLS()))
			},
			expectedBody: "<svg",
		},
		{
			name:      "Static endpoint not applied to custom domain",
			tlsRecord: true,
			prepare: func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet, root string) {
				planet.Uplinks[0].Access[planet.Satellites[0].NodeURL().ID] = newPaidAccess(ctx, t, planet.Satellites[0])
				require.NoError(t, planet.Uplinks[0].Upload(ctx, planet.Satellites[0], root, "static/img/logo.svg", []byte("HELLO!")))
			},
			url: func(t *testing.T, peer *linksharing.Peer, _, _, _, customDomain string) string {
				return fmt.Sprintf("https://%s/static/img/logo.svg", lookupHost(t, customDomain, peer.Server.AddrTLS()))
			},
		},
		{
			name: "Public domain landing page redirect",
			reconfigure: func(config *linksharing.Config) {
				config.Handler.LandingRedirectTarget = "https://www.storj.io/"
			},
			url: func(t *testing.T, peer *linksharing.Peer, accessKey, root, publicDomain, _ string) string {
				return fmt.Sprintf("http://%s/", lookupHost(t, publicDomain, peer.Server.Addr()))
			},
			wantRedirectResp:   true,
			redirectStatusCode: http.StatusSeeOther,
			redirectLocation: func(_ *testing.T, _ *linksharing.Peer, _, _, _, _ string) string {
				return "https://www.storj.io/"
			},
		},
		{
			name: "Public domain insecure",
			url: func(t *testing.T, peer *linksharing.Peer, accessKey, root, publicDomain, _ string) string {
				return fmt.Sprintf("http://%s/raw/%s/%s", lookupHost(t, publicDomain, peer.Server.Addr()), accessKey, root)
			},
			wantRedirectResp:   true,
			redirectStatusCode: http.StatusSeeOther,
			redirectLocation: func(t *testing.T, peer *linksharing.Peer, accessKey, root, _, _ string) string {
				return fmt.Sprintf("/raw/%s/%s/", accessKey, root)
			},
		},
		{
			name: "Public domain insecure redirect",
			reconfigure: func(config *linksharing.Config) {
				config.Handler.RedirectHTTPS = true
			},
			url: func(t *testing.T, peer *linksharing.Peer, accessKey, root, publicDomain, _ string) string {
				return fmt.Sprintf("http://%s/raw/%s/%s", lookupHost(t, publicDomain, peer.Server.Addr()), accessKey, root)
			},
			wantRedirectResp:   true,
			redirectStatusCode: http.StatusPermanentRedirect,
			redirectLocation: func(t *testing.T, peer *linksharing.Peer, accessKey, root, publicDomain, _ string) string {
				return fmt.Sprintf("https://%s/raw/%s/%s", lookupHost(t, publicDomain, peer.Server.Addr()), accessKey, root)
			},
		},
		{
			name: "Public domain insecure index.html",
			url: func(t *testing.T, peer *linksharing.Peer, accessKey, root, publicDomain, _ string) string {
				return fmt.Sprintf("http://%s/raw/%s/%s/index.html", lookupHost(t, publicDomain, peer.Server.Addr()), accessKey, root)
			},
		},
		{
			name: "Public domain insecure redirect with escaping",
			reconfigure: func(config *linksharing.Config) {
				config.Handler.RedirectHTTPS = true
			},
			url: func(t *testing.T, peer *linksharing.Peer, accessKey, root, publicDomain, _ string) string {
				return fmt.Sprintf("http://%s/s/%s/test%%20something.txt", lookupHost(t, publicDomain, peer.Server.Addr()), accessKey)
			},
			wantRedirectResp:   true,
			redirectStatusCode: http.StatusPermanentRedirect,
			redirectLocation: func(t *testing.T, peer *linksharing.Peer, accessKey, root, publicDomain, _ string) string {
				return fmt.Sprintf("https://%s/s/%s/test%%20something.txt", lookupHost(t, publicDomain, peer.Server.Addr()), accessKey)
			},
		},
		{
			name: "Public domain insecure redirect without /s or /raw prefix and with escaping",
			reconfigure: func(config *linksharing.Config) {
				config.Handler.RedirectHTTPS = true
			},
			url: func(t *testing.T, peer *linksharing.Peer, accessKey, root, publicDomain, _ string) string {
				return fmt.Sprintf("http://%s/%s/test%%20something.txt", lookupHost(t, publicDomain, peer.Server.Addr()), accessKey)
			},
			wantRedirectResp:   true,
			redirectStatusCode: http.StatusPermanentRedirect,
			redirectLocation: func(t *testing.T, peer *linksharing.Peer, accessKey, root, publicDomain, _ string) string {
				return fmt.Sprintf("https://%s/s/%s/test%%20something.txt", lookupHost(t, publicDomain, peer.Server.Addr()), accessKey)
			},
		},
		{
			name: "Public domain insecure redirect without /s or /raw prefix",
			url: func(t *testing.T, peer *linksharing.Peer, accessKey, root, publicDomain, _ string) string {
				return fmt.Sprintf("http://%s/%s/%s/index.html?download=1", lookupHost(t, publicDomain, peer.Server.Addr()), accessKey, root)
			},
			wantRedirectResp:   true,
			redirectStatusCode: http.StatusPermanentRedirect,
			redirectLocation: func(t *testing.T, peer *linksharing.Peer, accessKey, root, publicDomain, _ string) string {
				return fmt.Sprintf("http://%s/s/%s/%s/index.html?download=1", lookupHost(t, publicDomain, peer.Server.Addr()), accessKey, root)
			},
		},
		{
			name: "Public domain insecure redirect to HTTPS without /s or /raw prefix",
			reconfigure: func(config *linksharing.Config) {
				config.Handler.RedirectHTTPS = true
			},
			url: func(t *testing.T, peer *linksharing.Peer, accessKey, root, publicDomain, _ string) string {
				return fmt.Sprintf("http://%s/%s/%s/index.html?download=1", lookupHost(t, publicDomain, peer.Server.Addr()), accessKey, root)
			},
			wantRedirectResp:   true,
			redirectStatusCode: http.StatusPermanentRedirect,
			redirectLocation: func(t *testing.T, peer *linksharing.Peer, accessKey, root, publicDomain, _ string) string {
				return fmt.Sprintf("https://%s/s/%s/%s/index.html?download=1", lookupHost(t, publicDomain, peer.Server.Addr()), accessKey, root)
			},
		},
		{
			name: "Public domain secure redirect without /s or /raw prefix",
			reconfigure: func(config *linksharing.Config) {
				config.Handler.RedirectHTTPS = true
			},
			url: func(t *testing.T, peer *linksharing.Peer, accessKey, root, publicDomain, _ string) string {
				return fmt.Sprintf("https://%s/%s/%s/index.html?download=1", lookupHost(t, publicDomain, peer.Server.AddrTLS()), accessKey, root)
			},
			wantRedirectResp:   true,
			redirectStatusCode: http.StatusPermanentRedirect,
			redirectLocation: func(t *testing.T, peer *linksharing.Peer, accessKey, root, publicDomain, _ string) string {
				return fmt.Sprintf("https://%s/s/%s/%s/index.html?download=1", lookupHost(t, publicDomain, peer.Server.AddrTLS()), accessKey, root)
			},
		},
		{
			name: "Custom domain insecure",
			url: func(t *testing.T, peer *linksharing.Peer, _, _, _, customDomain string) string {
				return fmt.Sprintf("http://%s", lookupHost(t, customDomain, peer.Server.Addr()))
			},
		},
		{
			name: "Public domain TLS",
			url: func(t *testing.T, peer *linksharing.Peer, accessKey, root, publicDomain, _ string) string {
				return fmt.Sprintf("https://%s/raw/%s/%s/index.html", lookupHost(t, publicDomain, peer.Server.AddrTLS()), accessKey, root)
			},
		},
		{
			name: "Public domain TLS redirect",
			reconfigure: func(config *linksharing.Config) {
				config.Handler.RedirectHTTPS = true
			},
			url: func(t *testing.T, peer *linksharing.Peer, accessKey, root, publicDomain, _ string) string {
				return fmt.Sprintf("https://%s/raw/%s/%s/index.html", lookupHost(t, publicDomain, peer.Server.AddrTLS()), accessKey, root)
			},
			wantRedirectResp: false,
		},
		{
			name:      "Custom domain TLS TXT record disabled",
			tlsRecord: false,
			prepare: func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet, _ string) {
				planet.Uplinks[0].Access[planet.Satellites[0].NodeURL().ID] = newPaidAccess(ctx, t, planet.Satellites[0])
			},
			url: func(t *testing.T, peer *linksharing.Peer, _, _, _, customDomain string) string {
				return fmt.Sprintf("https://%s", lookupHost(t, customDomain, peer.Server.Addr()))
			},
			wantErr: true,
		},
		{
			name:      "Custom domain insecure TXT record disabled redirect",
			tlsRecord: false,
			reconfigure: func(config *linksharing.Config) {
				config.Handler.RedirectHTTPS = true
			},
			prepare: func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet, _ string) {
				planet.Uplinks[0].Access[planet.Satellites[0].NodeURL().ID] = newPaidAccess(ctx, t, planet.Satellites[0])
			},
			url: func(t *testing.T, peer *linksharing.Peer, _, _, _, customDomain string) string {
				return fmt.Sprintf("http://%s", lookupHost(t, customDomain, peer.Server.Addr()))
			},
			wantRedirectResp: false,
		},
		{
			name:      "Custom domain TLS not paid tier",
			tlsRecord: true,
			url: func(t *testing.T, peer *linksharing.Peer, _, _, _, customDomain string) string {
				return fmt.Sprintf("https://%s", lookupHost(t, customDomain, peer.Server.Addr()))
			},
			wantErr: true,
		},
		{
			name:        "Custom domain invalid CNAME",
			tlsRecord:   true,
			cnameRecord: "somethingelse.com.",
			dialContext: func(peer *linksharing.Peer) func(ctx context.Context, network, addr string) (net.Conn, error) {
				return func(ctx context.Context, network, addr string) (net.Conn, error) {
					return net.Dial(network, peer.Server.AddrTLS())
				}
			},
			prepare: func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet, _ string) {
				planet.Uplinks[0].Access[planet.Satellites[0].NodeURL().ID] = newPaidAccess(ctx, t, planet.Satellites[0])
			},
			url: func(t *testing.T, peer *linksharing.Peer, _, _, _, customDomain string) string {
				return fmt.Sprintf("https://%s", lookupHost(t, customDomain, peer.Server.AddrTLS()))
			},
			wantErr: true,
		},
		{
			name:      "Custom domain insecure paid tier",
			tlsRecord: true,
			prepare: func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet, _ string) {
				planet.Uplinks[0].Access[planet.Satellites[0].NodeURL().ID] = newPaidAccess(ctx, t, planet.Satellites[0])
			},
			url: func(t *testing.T, peer *linksharing.Peer, _, _, _, customDomain string) string {
				return fmt.Sprintf("http://%s", lookupHost(t, customDomain, peer.Server.Addr()))
			},
		},
		{
			name:      "Custom domain insecure paid tier redirect",
			tlsRecord: true,
			reconfigure: func(config *linksharing.Config) {
				config.Handler.RedirectHTTPS = true
			},
			prepare: func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet, _ string) {
				planet.Uplinks[0].Access[planet.Satellites[0].NodeURL().ID] = newPaidAccess(ctx, t, planet.Satellites[0])
			},
			url: func(t *testing.T, peer *linksharing.Peer, _, _, _, customDomain string) string {
				return fmt.Sprintf("http://%s", lookupHost(t, customDomain, peer.Server.Addr()))
			},
			wantRedirectResp:   true,
			redirectStatusCode: http.StatusPermanentRedirect,
			redirectLocation: func(t *testing.T, peer *linksharing.Peer, _, _, _, customDomain string) string {
				return fmt.Sprintf("https://%s/", lookupHost(t, customDomain, peer.Server.Addr()))
			},
		},
		{
			name:      "Custom domain insecure paid tier redirect with escaping",
			tlsRecord: true,
			reconfigure: func(config *linksharing.Config) {
				config.Handler.RedirectHTTPS = true
			},
			prepare: func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet, _ string) {
				planet.Uplinks[0].Access[planet.Satellites[0].NodeURL().ID] = newPaidAccess(ctx, t, planet.Satellites[0])
			},
			url: func(t *testing.T, peer *linksharing.Peer, _, _, _, customDomain string) string {
				return fmt.Sprintf("http://%s/test%%20something.txt", lookupHost(t, customDomain, peer.Server.Addr()))
			},
			wantRedirectResp:   true,
			redirectStatusCode: http.StatusPermanentRedirect,
			redirectLocation: func(t *testing.T, peer *linksharing.Peer, _, _, _, customDomain string) string {
				return fmt.Sprintf("https://%s/test%%20something.txt", lookupHost(t, customDomain, peer.Server.Addr()))
			},
		},
		{
			name:      "Custom domain TLS paid tier",
			tlsRecord: true,
			prepare: func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet, _ string) {
				planet.Uplinks[0].Access[planet.Satellites[0].NodeURL().ID] = newPaidAccess(ctx, t, planet.Satellites[0])
			},
			url: func(t *testing.T, peer *linksharing.Peer, _, _, _, customDomain string) string {
				return fmt.Sprintf("https://%s", lookupHost(t, customDomain, peer.Server.AddrTLS()))
			},
		},
		{
			name:      "Custom domain TLS paid tier redirect",
			tlsRecord: true,
			reconfigure: func(config *linksharing.Config) {
				config.Handler.RedirectHTTPS = true
			},
			prepare: func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet, _ string) {
				planet.Uplinks[0].Access[planet.Satellites[0].NodeURL().ID] = newPaidAccess(ctx, t, planet.Satellites[0])
			},
			url: func(t *testing.T, peer *linksharing.Peer, _, _, _, customDomain string) string {
				return fmt.Sprintf("https://%s", lookupHost(t, customDomain, peer.Server.AddrTLS()))
			},
			wantRedirectResp: false,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if tc.url == nil && tc.test == nil {
				t.Error("test misconfigured: url or test not defined", t.Name())
				return
			}

			ctx := testcontext.New(t)
			defer ctx.Cleanup()

			ident, err := testidentity.NewTestIdentity(ctx)
			require.NoError(t, err)

			testplanet.Run(t, testplanet.Config{
				SatelliteCount:   1,
				StorageNodeCount: 0,
				UplinkCount:      2,
				Reconfigure: testplanet.Reconfigure{
					Satellite: func(log *zap.Logger, index int, config *satellite.Config) {
						url, err := storj.ParseNodeURL(ident.ID.String() + "@")
						require.NoError(t, err)

						config.Userinfo.Enabled = true
						config.Userinfo.AllowedPeers = storj.NodeURLs{url}
					},
				},
			}, func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet) {
				// note that the host should be no more than 63 characters to be valid for DNS.
				root := testrand.BucketName()
				publicDomain := randomNameLowercase(40) + ".link.local"
				customDomain := randomNameLowercase(40) + ".example.com"

				if tc.prepare != nil {
					tc.prepare(t, ctx, planet, root)
				}

				var authRecords []authHandlerEntry
				for i := range planet.Uplinks {
					serializedAccess, err := planet.Uplinks[i].Access[planet.Satellites[0].NodeURL().ID].Serialize()
					require.NoError(t, err)

					authRecords = append(authRecords, authHandlerEntry{
						accessKey:        randomAccessKey(t),
						serializedAccess: serializedAccess,
						publicProjectID:  testrand.UUID(),
						public:           true,
					})
				}

				cnameRecord := publicDomain + "."
				if tc.cnameRecord != "" {
					cnameRecord = tc.cnameRecord
				}

				dnsRecords := map[string]mockdns.Zone{
					"localhost.": {
						A: []string{"127.0.0.1"},
					},
					publicDomain + ".": {
						A: []string{"127.0.0.1"},
					},
					customDomain + ".": {
						CNAME: cnameRecord,
					},
					"txt-" + customDomain + ".": {
						TXT: []string{
							"storj-access:" + authRecords[0].accessKey,
							"storj-root:" + root,
							"storj-tls:" + strconv.FormatBool(tc.tlsRecord),
						},
					},
				}

				runEnvironment(t, ctx, environmentConfig{
					gcsKeyPath:    gcsKeyPath,
					gcsBucketName: gcsBucketName,
					publicDomain:  publicDomain,
					ident:         ident,
					dnsRecords:    dnsRecords,
					authRecords:   authRecords,
					reconfigure:   tc.reconfigure,
				}, func(t *testing.T, ctx *testcontext.Context, peer *linksharing.Peer, caCertPool *x509.CertPool) {
					dialContext := (&mockdns.Resolver{Zones: dnsRecords}).DialContext
					if tc.dialContext != nil {
						dialContext = tc.dialContext(peer)
					}

					client := http.Client{Transport: &http.Transport{
						DialContext: dialContext,
						TLSClientConfig: &tls.Config{
							RootCAs: caCertPool,
						},
					}}

					if tc.test != nil {
						tc.test(t, ctx, peer, authRecords, publicDomain, customDomain, client)
						return
					}

					if tc.url == nil {
						t.Fatal("test misconfigured: url not defined", t.Name())
					}

					url := tc.url(t, peer, authRecords[0].accessKey, root, publicDomain, customDomain)

					if !tc.followRedirect {
						// Configure the HTTP client to not follow the redirect, so we can check it below.
						client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
							return http.ErrUseLastResponse
						}
					}

					require.NoError(t, planet.Uplinks[0].Upload(ctx, planet.Satellites[0], root, "index.html", []byte("HELLO!")))

					method := tc.method
					if method == "" {
						method = http.MethodGet
					}

					req, err := http.NewRequestWithContext(ctx, method, url, nil)
					require.NoError(t, err, url)

					resp, err := client.Do(req) //nolint:bodyclose
					if tc.wantErr {
						require.Error(t, err, url)
						return
					}

					require.NoError(t, err, url)
					defer ctx.Check(resp.Body.Close)

					expectedStatusCode := tc.expectedStatusCode
					if expectedStatusCode == 0 {
						expectedStatusCode = http.StatusOK
					}

					expectedBody := tc.expectedBody
					if expectedBody == "" && method != http.MethodOptions {
						expectedBody = "HELLO!"
					}

					if tc.expectedHeaders != nil {
						for k, v := range tc.expectedHeaders {
							require.Equal(t, v, resp.Header.Get(k), url)
						}
					}

					if !tc.wantRedirectResp {
						body, err := io.ReadAll(resp.Body)
						require.NoError(t, err, url)

						require.Equal(t, expectedStatusCode, resp.StatusCode)
						require.Contains(t, string(body), expectedBody, url)
						return
					}

					require.Equal(t, tc.redirectStatusCode, resp.StatusCode)
					redirectLocation := tc.redirectLocation(t, peer, authRecords[0].accessKey, root, publicDomain, customDomain)
					require.Equal(t, redirectLocation, resp.Header.Get("Location"))
				})
			})
		})
	}
}

type environmentConfig struct {
	gcsKeyPath    string
	gcsBucketName string
	publicDomain  string
	ident         *identity.FullIdentity
	dnsRecords    map[string]mockdns.Zone
	authRecords   []authHandlerEntry
	reconfigure   func(*linksharing.Config)
}

func runEnvironment(t *testing.T, ctx *testcontext.Context, config environmentConfig, fn func(t *testing.T, ctx *testcontext.Context, peer *linksharing.Peer, caCertPool *x509.CertPool)) {
	logger := zaptest.NewLogger(t)

	authToken := hex.EncodeToString(testrand.BytesInt(16))
	authServer := httptest.NewServer(makeAuthHandler(t, config.authRecords, authToken))
	defer authServer.Close()

	publicURLs := []string{"https://" + config.publicDomain}

	pebbleDomain := randomNameLowercase(40) + ".pebble.local"
	dnsRecords := config.dnsRecords
	dnsRecords[pebbleDomain+"."] = mockdns.Zone{
		A: []string{"127.0.0.1"},
	}

	dnsSrv, err := mockdns.NewServerWithLogger(dnsRecords, namedDebugStdLogger(t, logger, "mockdns"), true)
	require.NoError(t, err)
	defer ctx.Check(dnsSrv.Close)

	certTempPath := t.TempDir()

	identityConfig := identity.Config{
		CertPath: certTempPath + "/identity.crt",
		KeyPath:  certTempPath + "/identity.key",
	}
	require.NoError(t, identityConfig.Save(config.ident))

	issuer := createIssuer(t)
	pebbleCert := issuer.issue(t, []string{pebbleDomain})

	caCertPath := certTempPath + "/ca.crt"
	writeCertificate(t, caCertPath, issuer.CA)

	pebbleCertPath := certTempPath + "/pebble.crt"
	writeCertificate(t, pebbleCertPath, pebbleCert.Leaf)

	pebblePrivateKeyPath := certTempPath + "/pebble.key"
	writePrivateKey(t, pebblePrivateKeyPath, pebbleCert.PrivateKey)

	pebbleListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	// todo: we need to know the port up-front, because configureCertMagic()
	// looks at config.AddressTLS in order to determine AltTLSALPNPort.
	// If we tell the peer to listen on a random port with :0 then
	// AltTLSALPNPort is set to 0 because configureCertMagic only sees ":0"
	// instead of the randomly bound port. CertMagic will then attempt to start
	// a new listener on port 443 by default, which is not what we want.
	// We could change the peer to create the listener first and pass it
	// through to configureCertMagic() but until then we'll do this hacky
	// way of getting a random port by opening then closing a listener.
	tempListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addressTLS := tempListener.Addr().String()
	require.NoError(t, tempListener.Close())

	issuerURL := fmt.Sprintf("https://%s/dir", lookupHost(t, pebbleDomain, pebbleListener.Addr().String()))

	linksharingConfig := linksharing.Config{
		Server: httpserver.Config{
			Address:    "127.0.0.1:0",
			AddressTLS: addressTLS,
			TLSConfig: &httpserver.TLSConfig{
				CertMagic:      true,
				CertMagicEmail: "test@email.com",
				CertMagicTestIssuer: &httpserver.TestIssuerConfig{
					CA:              issuerURL,
					CertificatePath: caCertPath,
					Resolver:        dnsSrv.LocalAddr().String(),
				},
				CertMagicKeyFile: config.gcsKeyPath,
				CertMagicBucket:  config.gcsBucketName,
				TierService: tierquery.Config{
					Identity:        identityConfig,
					CacheExpiration: 10 * time.Second,
					CacheCapacity:   10000,
				},
				CertMagicPublicURLs: publicURLs,
				Ctx:                 ctx,
			},
			ShutdownTimeout: -1,
		},
		Handler: sharing.Config{
			Assets:       assets.FS(),
			URLBases:     publicURLs,
			TXTRecordTTL: 1 * time.Second,
			AuthServiceConfig: authclient.Config{
				BaseURL: authServer.URL,
				Token:   authToken,
			},
			DNSServer:     dnsSrv.LocalAddr().String(),
			ListPageLimit: 1,
		},
		ConcurrentRequestLimit: 1000,
		ShutdownDelay:          -1,
	}

	if config.reconfigure != nil {
		config.reconfigure(&linksharingConfig)
	}

	peer, err := linksharing.New(logger.Named("peer"), linksharingConfig)
	require.NoError(t, err)

	defer ctx.Check(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		return cleanupStorage(ctx, logger, config.gcsBucketName, config.gcsKeyPath, issuerURL)
	})

	defer ctx.Check(peer.Close)

	ctx.Go(func() error {
		return peer.Run(ctx)
	})

	pebbleLogger := logger.Named("pebble")

	db := db.NewMemoryStore()
	ca := ca.New(namedDebugStdLogger(t, pebbleLogger, "ca"), db, "", 0, 1, 600)
	va := va.New(namedDebugStdLogger(t, pebbleLogger, "va"), lookupPort(t, peer.Server.Addr()), lookupPort(t, peer.Server.AddrTLS()), true, dnsSrv.LocalAddr().String())
	wfeImpl := wfe.New(namedDebugStdLogger(t, pebbleLogger, "wfe"), db, va, ca, true, false)

	pebbleSrv := http.Server{Handler: wfeImpl.Handler()}
	defer ctx.Check(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		return pebbleSrv.Shutdown(ctx)
	})

	ctx.Go(func() error {
		err := pebbleSrv.ServeTLS(pebbleListener, pebbleCertPath, pebblePrivateKeyPath)
		if err != nil && !errs.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	})

	// pebble creates a new CA root and intermediate certificate on launch.
	intermediateCert := ca.GetIntermediateCert(0)
	require.NotNil(t, intermediateCert)

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(intermediateCert.Chain(0))

	fn(t, ctx, peer, caCertPool)
}

func findCredentials() (string, string, error) {
	gcsKeyPath := os.Getenv("STORJ_TEST_GCSTEST_PATH_TO_JSON_KEY")
	if gcsKeyPath == "" {
		return "", "", errs.New("STORJ_TEST_GCSTEST_PATH_TO_JSON_KEY is empty")
	}
	gcsBucketName := os.Getenv("STORJ_TEST_GCSTEST_BUCKET")
	if gcsBucketName == "" {
		return "", "", errs.New("STORJ_TEST_GCSTEST_BUCKET is empty")
	}

	return gcsKeyPath, gcsBucketName, nil
}

func randomNameLowercase(length int) string {
	return strings.ToLower(string(testrand.RandAlphaNumeric(length)))
}

func lookupHost(t *testing.T, host, hostPort string) string {
	_, port, err := net.SplitHostPort(hostPort)
	require.NoError(t, err)

	return net.JoinHostPort(host, port)
}

func lookupPort(t *testing.T, hostPort string) int {
	_, port, err := net.SplitHostPort(hostPort)
	require.NoError(t, err)

	lookupPort, err := net.LookupPort("tcp", port)
	require.NoError(t, err)

	return lookupPort
}

func newPaidAccess(ctx context.Context, t *testing.T, sat *testplanet.Satellite) *uplink.Access {
	name := string(testrand.RandAlphaNumeric(16))

	user, err := sat.AddUser(ctx, console.CreateUser{
		FullName: name,
		Email:    fmt.Sprintf("%s@email.com", name),
	}, 1)
	require.NoError(t, err)

	project, err := sat.AddProject(ctx, user.ID, "test")
	require.NoError(t, err)

	secret, err := macaroon.NewSecret()
	require.NoError(t, err)

	apiKey, err := macaroon.NewAPIKey(secret)
	require.NoError(t, err)

	_, err = sat.DB.Console().APIKeys().Create(ctx, apiKey.Head(), console.APIKeyInfo{
		Name:      "test",
		ProjectID: project.ID,
		Secret:    secret,
	})
	require.NoError(t, err)

	userCtx, err := sat.UserContext(ctx, user.ID)
	require.NoError(t, err)

	_, err = sat.API.Console.Service.Payments().AddCreditCard(userCtx, "test")
	require.NoError(t, err)

	encAccess := grant.NewEncryptionAccessWithDefaultKey(&storj.Key{})
	grantAccess := grant.Access{
		SatelliteAddress: sat.URL(),
		APIKey:           apiKey,
		EncAccess:        encAccess,
	}

	serializedAccess, err := grantAccess.Serialize()
	require.NoError(t, err)

	access, err := uplink.ParseAccess(serializedAccess)
	require.NoError(t, err)

	return access
}

type issuer struct {
	CA         *x509.Certificate
	PrivateKey crypto.PrivateKey
}

func (ca *issuer) issue(t *testing.T, dnsNames []string) tls.Certificate {
	rng := mathrand.New(mathrand.NewSource(mathrand.Int63()))

	nodeTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(int64(42)),
		NotAfter:              time.Now().Add(2 * time.Hour),
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{{127, 0, 0, 1}},
		DNSNames:              dnsNames,
	}

	pk, err := rsa.GenerateKey(rng, 4096)
	require.NoError(t, err)

	certDER, err := x509.CreateCertificate(rng, nodeTemplate, ca.CA, &pk.PublicKey, ca.PrivateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return tls.Certificate{
		PrivateKey:  pk,
		Leaf:        cert,
		Certificate: [][]byte{certDER},
	}
}

func createIssuer(t *testing.T) *issuer {
	rng := mathrand.New(mathrand.NewSource(mathrand.Int63()))

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		NotAfter:              time.Now().Add(2 * time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	privateKey, err := rsa.GenerateKey(rng, 4096)
	require.NoError(t, err)

	certDER, err := x509.CreateCertificate(rng, caTemplate, caTemplate, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return &issuer{
		CA:         cert,
		PrivateKey: privateKey,
	}
}

func writeCertificate(t *testing.T, path string, certs ...*x509.Certificate) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	require.NoError(t, err)

	require.NoError(t, peertls.WriteChain(file, certs...))
}

func writePrivateKey(t *testing.T, path string, key crypto.PrivateKey) {
	keyPEM, err := pkcrypto.PrivateKeyToPEM(key)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(path, keyPEM, 0600))
}

func cleanupStorage(ctx context.Context, logger *zap.Logger, bucket, jsonKeyPath, issuerURL string) error {
	jsonData, err := os.ReadFile(jsonKeyPath)
	if err != nil {
		return err
	}

	gcs, err := gcsops.NewClient(ctx, jsonData)
	if err != nil {
		return err
	}

	var kb certmagic.KeyBuilder
	var keys []string

	// unfortunately certmagic doesn't expose the issuer key building, so we have to do part of it ourselves.
	issuerKey := issuerKey(issuerURL)
	acmePrefix := path.Join("acme", kb.Safe(issuerKey))
	certsPrefix := kb.CertsPrefix(issuerKey)

	for _, prefix := range []string{acmePrefix, certsPrefix} {
		logger.Debug("listing objects from storage at prefix",
			zap.String("bucket", bucket),
			zap.String("prefix", prefix))

		list, err := gcs.List(ctx, bucket, prefix, true)
		if err != nil {
			return err
		}
		keys = append(keys, list...)
	}

	var errGroup errs.Group

	for _, key := range keys {
		logger.Debug("deleting object from storage",
			zap.String("bucket", bucket),
			zap.String("key", key))

		if err := gcs.Delete(ctx, nil, bucket, key); err != nil && !errs.Is(err, gcsops.ErrNotFound) {
			errGroup.Add(err)
		}
	}

	return errGroup.Err()
}

func issuerKey(ca string) string {
	key := ca
	if caURL, err := url.Parse(key); err == nil {
		key = caURL.Host
		if caURL.Path != "" {
			// keep the path, but make sure it's a single
			// component (i.e. no forward slashes, and for
			// good measure, no backward slashes either)
			const hyphen = "-"
			repl := strings.NewReplacer(
				"/", hyphen,
				"\\", hyphen,
			)
			path := strings.Trim(repl.Replace(caURL.Path), hyphen)
			if path != "" {
				key += hyphen + path
			}
		}
	}
	return key
}
