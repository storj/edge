// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/zeebo/errs"

	"storj.io/gateway-mt/pkg/authclient"
	"storj.io/uplink"
)

// TXTRecords fetches and caches linksharing DNS txt records.
type TXTRecords struct {
	maxTTL time.Duration
	dns    *DNSClient
	auth   *authclient.AuthClient

	cache       sync.Map
	updateLocks MutexGroup
}

type txtRecord struct {
	// TODO: storing the actual access grant in the cache saves us some
	// work and a request to the auth service, so that's nice. however,
	// by storing the actual access grant in the cache, the dns entry will
	// live until TTL *even though* the access key it used may have gotten
	// revoked sooner. this is a troubling problem for access keys, and
	// implies we should only support revoking access grants and not support
	// revoking access keys due to this confusion.
	access     *uplink.Access
	root       string
	tls        bool
	expiration time.Time
}

// NewTXTRecords constructs a TXTRecords.
func NewTXTRecords(maxTTL time.Duration, dns *DNSClient, auth *authclient.AuthClient) *TXTRecords {
	return &TXTRecords{
		maxTTL: maxTTL,
		dns:    dns,
		auth:   auth,
	}
}

// FetchAccessForHost fetches the root and access grant from the cache or dns
// server when applicable. clientIP is the IP of the client that originated the
// request.
func (records *TXTRecords) FetchAccessForHost(ctx context.Context, hostname string, clientIP string) (access *uplink.Access, root string, tls bool, err error) {
	defer mon.Task()(&ctx)(&err)

	val, ok := records.cache.Load(hostname)
	if !ok {
		// nothing in the cache, we have to go do a dns lookup before
		// we can return.
		record, err := records.updateCache(ctx, hostname, time.Time{}, clientIP)
		if err != nil {
			return nil, "", false, err
		}
		return record.access, record.root, record.tls, nil
	}

	// there's something in the cache!
	record := val.(*txtRecord)
	if record.expiration.Before(time.Now()) {
		// but it's expired. okay, this happens a lot and is usually going to
		// return the same value. we're going to be optimistic and assume the
		// value is right and return the expired value, but update the cache
		// in the background.
		// the user experience if the dns entry changes is that the user will
		// have to trigger a page load after the TTL expires to flush the
		// cache, but usually users test their pages after making changes, so
		// this should in practice be totally fine.
		// this strategy saves us the initial dns request round trip most
		// times.
		go func(ctx context.Context, hostname string, record *txtRecord) {
			_, _ = records.updateCache(ctx, hostname, record.expiration, clientIP)
		}(ctx, hostname, record)
	}

	return record.access, record.root, record.tls, nil
}

// updateCache will attempt to fetch and update the dns record for the given
// hostname. if there is a failure, updateCache will clear the cache and return
// the error. If currentExpiration is nil, updateCache will do nothing if there
// is already a cached value. If currentExpiration is set, updateCache will do
// nothing if the currently cached expiration is different than
// currentExpiration. clientIP is the IP of the client that originated the
// request.
func (records *TXTRecords) updateCache(ctx context.Context, hostname string, currentExpiration time.Time, clientIP string) (record *txtRecord, err error) {
	defer mon.Task()(&ctx)(&err)
	defer records.updateLocks.Lock(hostname)()

	// check if the call to us raced with another updateCache.
	if val, ok := records.cache.Load(hostname); ok {
		record = val.(*txtRecord)
		if currentExpiration.IsZero() || !record.expiration.Equal(currentExpiration) {
			return record, nil
		}
	}

	record, err = records.queryAccessFromDNS(ctx, hostname, clientIP)
	if err != nil {
		records.cache.Delete(hostname)
		return record, err
	}

	records.cache.Store(hostname, record)
	return record, nil
}

// queryAccessFromDNS does an txt record lookup for the hostname on the DNS
// server. clientIP is the IP of the client that originated the request and it's
// required to be sent to the Auth Service.
func (records *TXTRecords) queryAccessFromDNS(ctx context.Context, hostname string, clientIP string) (record *txtRecord, err error) {
	defer mon.Task()(&ctx)(&err)

	r, err := records.dns.Lookup(ctx, "txt-"+hostname, dns.TypeTXT)
	if err != nil {
		return nil, errs.New("failure with hostname %q: %w", hostname, err)
	}
	set := ResponseToTXTRecordSet(r)

	serializedAccess := set.Lookup("storj-access")
	if serializedAccess == "" {
		// backcompat
		serializedAccess = set.Lookup("storj-grant")
	}
	root := set.Lookup("storj-root")
	if root == "" {
		// backcompat
		root = set.Lookup("storj-path")
	}
	tls, _ := strconv.ParseBool(set.Lookup("storj-tls"))

	// NOTE(artur): due to cache shared among all clients per hostname for
	// hosting requests, signed requests cannot be served. One client with a
	// valid signed request could update the cache for all other clients. One
	// way to circumvent this would be to guess the signed request before and
	// disable cache in that path. However, this requires major refactoring.
	access, err := parseAccess(ctx, nil, serializedAccess, 0, records.auth, clientIP)
	if err != nil {
		return nil, errs.New("failure with hostname %q: %w", hostname, err)
	}

	ttl := set.TTL()
	if ttl > records.maxTTL {
		ttl = records.maxTTL
	}

	return &txtRecord{access: access, root: root, tls: tls, expiration: time.Now().Add(ttl)}, nil
}
