// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"net/http"
	"sync"

	"storj.io/common/grant"
)

// NewConcurrentRequestsLimiter constructs a Limiter that limits using a key from credentials.
// It relies on the AccessKey middleware being run to append credentials to the request context.
func NewConcurrentRequestsLimiter(allowed uint, limitFunc func(w http.ResponseWriter, r *http.Request)) *Limiter {
	return NewLimiter(allowed, getLimitKey, limitFunc)
}

// getLimitKey retrieves a key used to identify the user for limiting requests.
func getLimitKey(r *http.Request) (identifier string, err error) {
	credentials := GetAccess(r.Context())
	if credentials == nil || credentials.AccessGrant == "" {
		return "", ParseV4CredentialError.New("missing access grant")
	}
	if credentials.PublicProjectID != "" {
		return credentials.PublicProjectID, nil
	}

	// fallback to macaroon head if the credentials don't contain public project ID. This is likely because the
	// authservice record is old and hasn't been backfilled with the ID yet, or the ID couldn't be resolved due
	// to a connectivity issue between authservice and the satellite.
	access, err := grant.ParseAccess(credentials.AccessGrant)
	if err != nil {
		return "", err
	}

	return string(access.APIKey.Head()), err
}

// Limiter imposes a limit per key.
type Limiter struct {
	allowed   uint // maximum concurrent allowed
	keyFunc   func(*http.Request) (string, error)
	limitFunc func(w http.ResponseWriter, r *http.Request)

	limits map[string]uint
	m      sync.RWMutex
}

// NewLimiter constructs a concurrency Limiter. Error and Limit functions are user defined
// in part because referencing the "minio" package here would cause an import loop.
func NewLimiter(allowed uint, keyFunc func(*http.Request) (string, error), limitFunc func(w http.ResponseWriter, r *http.Request)) *Limiter {
	return &Limiter{
		allowed:   allowed,
		limits:    make(map[string]uint),
		keyFunc:   keyFunc,
		limitFunc: limitFunc,
	}
}

// Limit applies per-key request concurrency limiting as an HTTP middleware.
func (l *Limiter) Limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		ctx := r.Context()
		defer mon.TaskNamed("Limit")(&ctx)(&err)
		key, err := l.keyFunc(r)
		if err != nil {
			// its easiest to let other parts of the code handle auth errors
			// we do want to continue rate limiting all unauthorized users
			key = ""
		}
		l.m.Lock()
		l.limits[key]++
		l.m.Unlock()
		l.m.RLock()
		if l.limits[key] > l.allowed {
			l.m.RUnlock()
			l.limitFunc(w, r)
		} else {
			l.m.RUnlock()
			next.ServeHTTP(w, r)
		}
		l.m.Lock()
		l.limits[key]--
		if l.limits[key] == 0 {
			delete(l.limits, key)
		}
		l.m.Unlock()
	})
}
