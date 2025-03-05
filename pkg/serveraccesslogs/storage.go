// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package serveraccesslogs

import (
	"bytes"
	"context"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"

	"storj.io/common/sync2"
	"storj.io/uplink"
)

var mon = monkit.Package()

// StorjStorage is an implementation of Storage that allows uploading to
// Storj via libuplink.
type StorjStorage struct {
	access *uplink.Access
}

// NewStorjStorage creates a new instance of StorjStorage with the given access grant.
// It initializes and returns a pointer to the StorjStorage struct.
func NewStorjStorage(access *uplink.Access) *StorjStorage {
	return &StorjStorage{
		access: access,
	}
}

// SerializedAccessGrant returns a serialized form of the access grant used for this storage.
func (s StorjStorage) SerializedAccessGrant() (string, error) {
	return s.access.Serialize()
}

// Put saves body under bucket/key to Storj.
func (s StorjStorage) Put(ctx context.Context, bucket, key string, body []byte) (err error) {
	defer mon.Task()(&ctx)(&err)

	p, err := uplink.OpenProject(ctx, s.access)
	if err != nil {
		return err
	}
	defer func() { err = errs.Combine(err, p.Close()) }()
	u, err := p.UploadObject(ctx, bucket, key, nil)
	if err != nil {
		return err
	}
	if _, err = sync2.Copy(ctx, u, bytes.NewBuffer(body)); err != nil {
		return errs.Combine(err, u.Abort())
	}
	return u.Commit()
}
