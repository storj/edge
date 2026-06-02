// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package httpserver

import (
	"net"
	"net/http"
	"strings"
)

// ClientIP returns the client's IP. Headers are consulted in this order, and
// the first one present wins:
//
//  1. Forwarded (RFC 7239) — the last for= directive
//  2. X-Forwarded-For — the last entry
//  3. X-Real-Ip
//
// If none of those are set, r.RemoteAddr is returned with any port stripped.
func ClientIP(r *http.Request) string {
	if ip := forwardedFor(r.Header.Get("Forwarded")); ip != "" {
		return ip
	}
	if h := r.Header.Get("X-Forwarded-For"); h != "" {
		ips := strings.Split(h, ",")
		return strings.TrimSpace(ips[len(ips)-1])
	}
	if h := r.Header.Get("X-Real-Ip"); h != "" {
		return strings.TrimSpace(h)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// forwardedFor returns the IP from the last for= directive in an RFC 7239
// Forwarded header value, with any port and IPv6 brackets stripped. Returns ""
// if no for= directive is present.
func forwardedFor(h string) string {
	if h == "" {
		return ""
	}
	elements := strings.Split(h, ",")
	last := strings.TrimSpace(elements[len(elements)-1])
	for _, pair := range strings.Split(last, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if !ok || !strings.EqualFold(k, "for") {
			continue
		}
		v = strings.Trim(v, `"`)
		if host, _, err := net.SplitHostPort(v); err == nil {
			return host
		}
		return strings.Trim(v, "[]")
	}
	return ""
}
