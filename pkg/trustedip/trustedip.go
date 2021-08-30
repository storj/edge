// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package trustedip

import (
	"net/http"
	"regexp"
	"strings"
)

// List is a list of trusted IPs for conveniently verifying if an IP is trusted.
type List struct {
	// ips is the list of trusted IPs. It's used when untrustAll is false. When
	// empty it trusts any IP.
	ips        map[string]struct{}
	untrustAll bool
}

// NewListUntrustAll creates a new List which doesn't trust in any IP.
func NewListUntrustAll() List {
	return List{untrustAll: true}
}

// NewListTrustAll creates a new List which trusts any IP.
func NewListTrustAll() List {
	return List{}
}

// NewListTrustIPs creates a new List which trusts the passed ips.
//
// NOTE: ips are not checked to be well formatted and their values are what they
// kept in the list.
func NewListTrustIPs(ips ...string) List {
	l := List{ips: make(map[string]struct{}, len(ips))}

	for _, ip := range ips {
		l.ips[ip] = struct{}{}
	}

	return l
}

// IsTrusted returns true if ip is trusted, otherwise false.
func (l List) IsTrusted(ip string) bool {
	if l.untrustAll {
		return false
	}

	if len(l.ips) == 0 {
		return true
	}

	_, ok := l.ips[ip]
	return ok
}

var forwardForClientIPRegExp = regexp.MustCompile(`for=([^,; ]+)`)

// GetClientIP gets the IP of the client from the 'Forwarded',
// 'X-Forwarded-For', or 'X-Real-Ip' headers if r.RemoteAddr is a trusted IP and
// returning it from the first header which are checked in that specific order.
// If the IP isn't trusted then it returns r.RemoteAddr. It panics if r is nil.
//
// NOTE: it doesn't check that the IP value get from wherever source is a well
// formatted IP v4 nor v6.
func GetClientIP(l List, r *http.Request) string {
	if l.IsTrusted(r.RemoteAddr) {
		header := r.Header.Get("Forwarded")
		if header != "" {
			// Get the first value of the 'for' identifier present in the header
			// because it's the one that contains the client IP.
			// See https://datatracker.ietf.org/doc/html/rfc7230
			matches := forwardForClientIPRegExp.FindStringSubmatch(header)
			if len(matches) > 1 {
				return matches[1]
			}
		}

		header = r.Header.Get("X-Forwarded-For")
		if header != "" {
			// Get the first the value IP because it's the client IP.
			// Header syntax: X-Forwarded-For: <client>, <proxy1>, <proxy2>
			// See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For
			ips := strings.SplitN(header, ",", 2)
			if len(ips) > 0 {
				return ips[0]
			}
		}

		header = r.Header.Get("X-Real-Ip")
		if header != "" {
			// Get the value of the header because its value is just the client
			// IP. This header is mostly sent by NGINX.
			// See https://www.nginx.com/resources/wiki/start/topics/examples/forwarded/
			return header
		}
	}

	// Ensure to strip the port out if r.RemoteAddr has it.
	return strings.SplitN(r.RemoteAddr, ":", 2)[0]
}
