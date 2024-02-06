// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"gopkg.in/webhelp.v1/whmon"
	"gopkg.in/webhelp.v1/whroute"

	"storj.io/common/useragent"
	"storj.io/edge/pkg/auth/authdb"
	"storj.io/edge/pkg/httplog"
	"storj.io/edge/pkg/trustedip"
	"storj.io/eventkit"
	privateAccess "storj.io/uplink/private/access"
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

			var macHead, encKeyHash, satelliteAddress, hostingRoot string
			var hostingTLS bool
			creds := credentialsFromContext(r.Context())
			if creds != nil {
				if creds.access != nil {
					macHead = hex.EncodeToString(privateAccess.APIKey(creds.access).Head())
					satelliteAddress = creds.access.SatelliteAddress()
				}

				// creds.serializedAccess could be either an access key or grant.
				if len(creds.serializedAccess) == authdb.EncKeySizeEncoded {
					var key authdb.EncryptionKey
					if err := key.FromBase32(creds.serializedAccess); err == nil {
						encKeyHash = key.Hash().ToHex()
					}
				}

				hostingRoot = creds.hostingRoot
				hostingTLS = creds.hostingTLS
			}

			h.ServeHTTP(w, r)

			if !rw.WroteHeader() {
				rw.WriteHeader(http.StatusOK)
			}

			var queryJSON, requestHeadersJSON, responseHeadersJSON string
			if b, err := json.Marshal(&httplog.RequestQueryLogObject{Query: r.URL.Query()}); err == nil {
				queryJSON = string(b)
			}
			if b, err := json.Marshal(&httplog.HeadersLogObject{Headers: r.Header}); err == nil {
				requestHeadersJSON = string(b)
			}
			if b, err := json.Marshal(&httplog.HeadersLogObject{Headers: rw.Header()}); err == nil {
				responseHeadersJSON = string(b)
			}

			ek.Event("present",
				eventkit.String("protocol", r.Proto),
				eventkit.String("host", r.Host),
				eventkit.String("method", r.Method),
				eventkit.Bool("hosting", hostingRoot != ""),
				eventkit.Bool("hosting-tls", hostingTLS),
				eventkit.String("user-agent", product),
				eventkit.Int64("status", int64(rw.StatusCode())),
				eventkit.Int64("request-size", r.ContentLength),
				eventkit.Int64("response-size", rw.Written()),
				eventkit.Duration("duration", time.Since(start)),
				eventkit.String("encryption-key-hash", encKeyHash),
				eventkit.String("macaroon-head", macHead),
				eventkit.String("satellite-address", satelliteAddress),
				eventkit.String("remote-ip", trustedip.GetClientIP(trustedip.NewListTrustAll(), r)),
				eventkit.String("query", queryJSON),
				eventkit.String("request-headers", requestHeadersJSON),
				eventkit.String("response-headers", responseHeadersJSON))
		}))
}
