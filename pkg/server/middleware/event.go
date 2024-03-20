// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"gopkg.in/webhelp.v1/whmon"
	"gopkg.in/webhelp.v1/whroute"

	"storj.io/common/grant"
	"storj.io/common/http/requestid"
	"storj.io/common/useragent"
	"storj.io/edge/pkg/auth/authdb"
	"storj.io/edge/pkg/httplog"
	"storj.io/edge/pkg/server/gwlog"
	"storj.io/edge/pkg/trustedip"
	"storj.io/eventkit"
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

			var macHead, encKeyHash, satelliteAddress string
			credentials := GetAccess(r.Context())
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
			}

			gl, ok := gwlog.FromContext(r.Context())
			if !ok {
				gl = gwlog.New()
				r = r.WithContext(gl.WithContext(r.Context()))
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
				eventkit.String("satellite-address", satelliteAddress),
				eventkit.String("remote-ip", trustedip.GetClientIP(trustedip.NewListTrustAll(), r)),
				eventkit.String("error", gl.TagValue("error")),
				eventkit.String("request-id", requestid.FromContext(r.Context())),
				eventkit.String("amz-request-id", gl.RequestID),
				eventkit.String("trace-id", rw.Header().Get("trace-id")),
				eventkit.String("api-operation", gl.API),
				eventkit.String("query", queryJSON),
				eventkit.String("request-headers", requestHeadersJSON),
				eventkit.String("response-headers", responseHeadersJSON))
		}))
}
