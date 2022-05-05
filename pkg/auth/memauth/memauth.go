// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package memauth

import (
	"context"
	"sync"
	"time"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"

	"storj.io/gateway-mt/pkg/auth/authdb"
)

var mon = monkit.Package()

// KV is a key/value store backed by an in memory map.
type KV struct {
	mu      sync.Mutex
	entries map[authdb.KeyHash]*authdb.Record
}

// New constructs a KV.
func New() *KV {
	return &KV{
		entries: make(map[authdb.KeyHash]*authdb.Record),
	}
}

// Put stores the record in the key/value store.
// It is an error if the key already exists.
func (d *KV) Put(ctx context.Context, keyHash authdb.KeyHash, record *authdb.Record) (err error) {
	defer mon.Task()(&ctx)(&err)

	d.mu.Lock()
	defer d.mu.Unlock()

	if _, ok := d.entries[keyHash]; ok {
		return errs.New("record already exists")
	}

	d.entries[keyHash] = record
	return nil
}

// Get retrieves the record from the key/value store.
// It returns nil if the key does not exist.
func (d *KV) Get(ctx context.Context, keyHash authdb.KeyHash) (record *authdb.Record, err error) {
	defer mon.Task()(&ctx)(&err)

	d.mu.Lock()
	defer d.mu.Unlock()

	return d.entries[keyHash], nil
}

// DeleteUnused deletes expired and invalid records from the key/value store and
// returns any error encountered. It does not perform batch deletion of records.
func (d *KV) DeleteUnused(ctx context.Context, _ time.Duration, _, _ int) (count, rounds int64, deletesPerHead map[string]int64, err error) {
	defer mon.Task()(&ctx)(&err)

	deletesPerHead = make(map[string]int64)

	d.mu.Lock()
	defer d.mu.Unlock()

	for k, v := range d.entries {
		if v != nil && v.ExpiresAt != nil && time.Now().After(*v.ExpiresAt) {
			count++
			deletesPerHead[string(v.MacaroonHead)]++
			delete(d.entries, k)
		}
	}

	return count, 1, deletesPerHead, nil
}

// PingDB attempts to do a database roundtrip and returns an error if it can't.
func (d *KV) PingDB(context.Context) error { return nil }

// Close closes the database.
func (d *KV) Close() error { return nil }

// Run runs the database.
func (d *KV) Run(ctx context.Context) error { return nil }
