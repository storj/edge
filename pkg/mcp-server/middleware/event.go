// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"encoding/hex"
	"net/http"
	"time"

	"gopkg.in/webhelp.v1/whmon"
	"gopkg.in/webhelp.v1/whroute"

	"storj.io/common/grant"
	"storj.io/common/http/requestid"
	"storj.io/common/useragent"
	"storj.io/edge/pkg/auth/authdb"
	"storj.io/edge/pkg/trustedip"
	"storj.io/eventkit"
)

var ek = eventkit.Package()

// EventHandler collects event data to send to eventkit.
func EventHandler(h http.Handler) http.Handler {
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

			var macHead, encKeyHash, satelliteAddress, publicProjectID string
			credentials := GetCredentials(r.Context())
			if credentials != nil {
				if credentials.AccessGrant != "" {
					if access, err := grant.ParseAccess(credentials.AccessGrant); err == nil {
						macHead = hex.EncodeToString(access.APIKey.Head())
						satelliteAddress = access.SatelliteAddress
					}
				}
				if credentials.AccessKey != "" {
					var key authdb.EncryptionKey
					if err := key.FromBase32(credentials.AccessKey); err == nil {
						encKeyHash = key.Hash().ToHex()
					}
				}
				publicProjectID = credentials.PublicProjectID
			}

			h.ServeHTTP(w, r)

			if !rw.WroteHeader() {
				rw.WriteHeader(http.StatusOK)
			}

			ek.Event("response",
				eventkit.String("protocol", r.Proto),
				eventkit.String("host", r.Host),
				eventkit.String("method", r.Method),
				eventkit.String("request-uri", r.RequestURI),
				eventkit.String("user-agent", product),
				eventkit.Int64("status", int64(rw.StatusCode())),
				eventkit.Int64("request-size", r.ContentLength),
				eventkit.Int64("response-size", rw.Written()),
				eventkit.Duration("duration", time.Since(start)),
				eventkit.String("public-project-id", publicProjectID),
				eventkit.String("encryption-key-hash", encKeyHash),
				eventkit.String("macaroon-head", macHead),
				eventkit.String("satellite-address", satelliteAddress),
				eventkit.String("remote-ip", trustedip.GetClientIP(trustedip.NewListTrustAll(), r)),
				eventkit.String("request-id", requestid.FromContext(r.Context())))
		}))
}
