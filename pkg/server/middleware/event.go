// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"encoding/hex"
	"net/http"

	"github.com/jtolio/eventkit"

	"storj.io/common/grant"
	"storj.io/common/useragent"
	"storj.io/gateway-mt/pkg/trustedip"
)

var ek = eventkit.Package()

// CollectEvent collects event data to send to eventkit.
func CollectEvent(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agents, err := useragent.ParseEntries([]byte(r.UserAgent()))
		product := "unknown"
		if err == nil && len(agents) > 0 && agents[0].Product != "" {
			product = agents[0].Product
			if len(product) > 32 {
				product = product[:32]
			}
		}

		var macHead string
		credentials := GetAccess(r.Context())
		if credentials != nil && credentials.AccessGrant != "" {
			access, err := grant.ParseAccess(credentials.AccessGrant)
			if err == nil {
				macHead = hex.EncodeToString(access.APIKey.Head())
			}
		}

		ek.Event("gmt",
			eventkit.String("user-agent", product),
			eventkit.String("macaroon-head", macHead),
			eventkit.String("remote-ip", trustedip.GetClientIP(trustedip.NewListTrustAll(), r)))

		next.ServeHTTP(w, r)
	})
}
