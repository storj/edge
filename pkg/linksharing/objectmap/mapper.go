// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package objectmap

import (
	"context"
	"net"
	"strings"
	"sync"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
)

var mon = monkit.Package()

// Error is the default error class for objectmap.
var Error = errs.Class("objectmap error")

// IPInfo represents the geolocation data from maxmind db.
type IPInfo struct {
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

// Reader is a maxmind database reader interface.
type Reader interface {
	Lookup(ip net.IP, result interface{}) error
	Close() error
}

type cachedInfo struct {
	Error error
	IPInfo
}

// IPDB holds the database file path and its reader.
//
// architecture: Database
type IPDB struct {
	reader Reader

	mu        sync.RWMutex
	cachedIPs map[string]cachedInfo
}

// NewIPDB creates a new IPMapper instance.
func NewIPDB(reader Reader) *IPDB {
	return &IPDB{
		reader:    reader,
		cachedIPs: make(map[string]cachedInfo),
	}
}

// Close closes the IPMapper reader.
func (mapper *IPDB) Close() (err error) {
	if mapper.reader != nil {
		return mapper.reader.Close()
	}
	return nil
}

// GetIPInfos returns the geolocation information from an IP address.
func (mapper *IPDB) GetIPInfos(ctx context.Context, hostOrIP string) (_ *IPInfo, err error) {
	defer mon.Task()(&ctx)(&err)

	mapper.mu.RLock()
	cacheItem, ok := mapper.cachedIPs[hostOrIP]
	mapper.mu.RUnlock()

	if ok {
		if cacheItem.Error != nil {
			return nil, cacheItem.Error
		}
		return &cacheItem.IPInfo, nil
	}

	parsed, err := mapper.parseHost(hostOrIP)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	var record IPInfo
	err = mapper.reader.Lookup(parsed, &record)

	mapper.mu.Lock()
	mapper.cachedIPs[hostOrIP] = cachedInfo{
		Error:  err,
		IPInfo: record,
	}
	mapper.mu.Unlock()

	if err != nil {
		return nil, Error.Wrap(err)
	}
	return &record, nil
}

// parseHost validate and remove port from IP address.
func (mapper *IPDB) parseHost(hostOrIP string) (_ net.IP, err error) {
	if strings.Count(hostOrIP, ":") > 1 {
		return nil, errs.New("IPv6 addresses are ignored for now: %s", hostOrIP)
	}

	ip, _, err := net.SplitHostPort(hostOrIP)
	if err != nil {
		ip = hostOrIP // assume it had no port
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil, errs.New("invalid IP address: %s", ip)
	}
	return parsed, nil
}
