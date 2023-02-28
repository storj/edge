// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"encoding/hex"
	"net/http"
	"time"

	"github.com/jtolio/eventkit"
	"gopkg.in/webhelp.v1/whmon"
	"gopkg.in/webhelp.v1/whroute"

	"storj.io/common/grant"
	"storj.io/common/useragent"
	"storj.io/gateway-mt/pkg/auth/authdb"
	"storj.io/gateway-mt/pkg/trustedip"
)

var ek = eventkit.Package()

// CollectEvent collects event data to send to eventkit.
func CollectEvent(h http.Handler) http.Handler {
	return whmon.MonitorResponse(whroute.HandlerFunc(h,
		func(w http.ResponseWriter, r *http.Request) {
			rw := w.(whmon.ResponseWriter)
			start := time.Now()

			agents, err := useragent.ParseEntries([]byte(r.UserAgent()))
			product := "unknown"
			if err == nil && len(agents) > 0 && agents[0].Product != "" {
				product = agents[0].Product
				if len(product) > 32 {
					product = product[:32]
				}
			}

			var macHead, encKeyHash string
			credentials := GetAccess(r.Context())
			if credentials != nil {
				if credentials.AccessGrant != "" {
					access, err := grant.ParseAccess(credentials.AccessGrant)
					if err == nil {
						macHead = hex.EncodeToString(access.APIKey.Head())
					}
				}
				if credentials.AccessKey != "" {
					var key authdb.EncryptionKey
					if err := key.FromBase32(credentials.AccessKey); err == nil {
						encKeyHash = key.Hash().ToHex()
					}
				}
			}

			h.ServeHTTP(w, r)

			if !rw.WroteHeader() {
				rw.WriteHeader(http.StatusOK)
			}

			ek.Event("gmt",
				eventkit.String("protocol", r.Proto),
				eventkit.String("method", r.Method),
				eventkit.String("user-agent", product),
				eventkit.Int64("status", int64(rw.StatusCode())),
				eventkit.Int64("request-size", r.ContentLength),
				eventkit.Int64("response-size", rw.Written()),
				eventkit.Duration("duration", time.Since(start)),
				eventkit.String("encryption-key-hash", encKeyHash),
				eventkit.String("macaroon-head", macHead),
				eventkit.String("remote-ip", trustedip.GetClientIP(trustedip.NewListTrustAll(), r)))
		}))
}
