// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// queryFlagLookup finds a boolean value in a url.Values struct, returning
// defValue if not found.
//  * no flag is the default value
//  * ?flag is assumed true
//  * ?flag=no (or false or 0 or off) is assumed false (case insensitive)
//  * everything else is true
func queryFlagLookup(q url.Values, name string, defValue bool) bool {
	vals, ok := q[name]
	if !ok || len(vals) == 0 {
		// the flag wasn't specified
		return defValue
	}
	val := vals[0]
	if len(val) == 0 {
		// the flag was specified, but no value was provided. must be form of
		// ?flag or ?flag= but no value. assume that means on.
		return true
	}
	switch strings.ToLower(val) {
	case "no", "false", "0", "off":
		// cases where the flag is false
		return false
	}
	return true
}

// queryIntLookup finds an integer value in a url.Values struct, returning
// defValue if not found or invalid.
func queryIntLookup(q url.Values, name string, defValue int) int {
	if vals, ok := q[name]; ok && len(vals) > 0 {
		if val, err := strconv.Atoi(vals[0]); err == nil {
			return val
		}
	}
	return defValue
}

// MutexGroup is a group of mutexes by name that attempts to only keep track of
// live mutexes. The zero value is okay to use.
type MutexGroup struct {
	mu      sync.Mutex
	names   map[string]*sync.Mutex
	waiters map[string]int
}

func (m *MutexGroup) init(name string) {
	if m.names == nil {
		m.names = map[string]*sync.Mutex{name: new(sync.Mutex)}
		m.waiters = map[string]int{}
		return
	}
	if _, exists := m.names[name]; !exists {
		m.names[name] = &sync.Mutex{}
	}
}

// Lock will lock the mutex named by name. It will return the appropriate
// function to call to unlock that lock.
func (m *MutexGroup) Lock(name string) (unlock func()) {
	m.mu.Lock()
	m.init(name)
	namedMu := m.names[name]
	m.waiters[name]++
	m.mu.Unlock()
	namedMu.Lock()
	return func() {
		namedMu.Unlock()
		m.mu.Lock()
		waiting := m.waiters[name] - 1
		m.waiters[name] = waiting
		if waiting <= 0 {
			if waiting < 0 {
				panic("double unlock")
			}
			delete(m.names, name)
			delete(m.waiters, name)
		}
		m.mu.Unlock()
	}
}

// ExponentialBackoff keeps track of how long we should sleep between
// failing attempts.
type ExponentialBackoff struct {
	delay time.Duration
	Max   time.Duration
	Min   time.Duration
}

func (e *ExponentialBackoff) init() {
	if e.Max == 0 {
		// maximum delay - pulled from net/http.Server.Serve
		e.Max = time.Second
	}
	if e.Min == 0 {
		// minimum delay - pulled from net/http.Server.Serve
		e.Min = 5 * time.Millisecond
	}
}

// Wait should be called when there is a failure. Each time it is called
// it will sleep an exponentially longer time, up to a max.
func (e *ExponentialBackoff) Wait(ctx context.Context) error {
	e.init()
	if e.delay == 0 {
		e.delay = e.Min
	} else {
		e.delay *= 2
	}
	if e.delay > e.Max {
		e.delay = e.Max
	}

	if ctx.Err() != nil {
		return ctx.Err()
	}

	t := time.NewTimer(e.delay)
	defer t.Stop()

	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Maxed returns true if the wait time has maxed out.
func (e *ExponentialBackoff) Maxed() bool {
	e.init()
	return e.delay == e.Max
}

type trustedIPsList struct {
	// ips is the list of trusted IPs. It's used when untrustAll is false. When
	// empty it trusts any IP.
	ips        map[string]struct{}
	untrustAll bool
}

// newTrustedIPsListUntrustAll creates a new trustedIPsList which doesn't trust in
// any IP.
func newTrustedIPsListUntrustAll() trustedIPsList {
	return trustedIPsList{untrustAll: true}
}

// newTrustedIPsListTrustAll creates a new trustedIPsList which trusts any IP.
func newTrustedIPsListTrustAll() trustedIPsList {
	return trustedIPsList{}
}

// newTrustedIPsListTrustIPs creates a new trustedIPsList which trusts the passed
// ips.
//
// NOTE: ips are not checked to be well formatted and their values are what they
// kept in the list.
func newTrustedIPsListTrustIPs(ips ...string) trustedIPsList {
	tipl := trustedIPsList{ips: make(map[string]struct{}, len(ips))}

	for _, ip := range ips {
		tipl.ips[ip] = struct{}{}
	}

	return tipl
}

// IsTrusted returns true ip is trusted, otherwise false.
func (tipl trustedIPsList) IsTrusted(ip string) bool {
	if tipl.untrustAll {
		return false
	}

	if len(tipl.ips) == 0 {
		return true
	}

	_, ok := tipl.ips[ip]
	return ok
}

var forwardForClientIPRegExp = regexp.MustCompile(`for=([^,; ]+)`)

// getClientIP gets the IP of the client from the 'Forwarded',
// 'X-Forwarded-For', or 'X-Real-Ip' headers if r.RemoteAddr is a trusted IP and
// returning it from the first header which are checked in that specific order.
// If the IP isn't rusted then it returns r.RemoteAddr.
// It panics if r is nil.
//
// NOTE: it doesn't check that the IP value get from wherever source is a well
// formatted IP v4 nor v6.
func getClientIP(tipl trustedIPsList, r *http.Request) string {
	if tipl.IsTrusted(r.RemoteAddr) {
		header := r.Header.Get("Forwarded")
		if header != "" {
			// Get the first value of the 'for' identifier present in the header because
			// its the one that contains the client IP.
			// see: https://datatracker.ietf.org/doc/html/rfc7230
			matches := forwardForClientIPRegExp.FindStringSubmatch(header)
			if len(matches) > 1 {
				return matches[1]
			}
		}

		header = r.Header.Get("X-Forwarded-For")
		if header != "" {
			// Get the first the value IP because it's the client IP.
			// Header sysntax: X-Forwarded-For: <client>, <proxy1>, <proxy2>
			// See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For
			ips := strings.SplitN(header, ",", 2)
			if len(ips) > 0 {
				return ips[0]
			}
		}

		header = r.Header.Get("X-Real-Ip")
		if header != "" {
			// Get the value of the header because its value is just the client IP.
			// This header is mostly sent by NGINX.
			// See https://www.nginx.com/resources/wiki/start/topics/examples/forwarded/
			return header
		}
	}

	// Ensure to strip the port out if r.RemoteAddr has it.
	return strings.SplitN(r.RemoteAddr, ":", 2)[0]
}
