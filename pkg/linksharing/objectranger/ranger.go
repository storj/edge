// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package objectranger

import (
	"context"
	"io"

	"github.com/spacemonkeygo/monkit/v3"

	"storj.io/common/ranger"
	"storj.io/uplink"
)

var (
	mon = monkit.Package()
)

// ObjectRanger holds all the data needed to make object downloadable.
type ObjectRanger struct {
	p      *uplink.Project
	o      *uplink.Object
	bucket string
}

// New creates a new object ranger.
func New(p *uplink.Project, o *uplink.Object, bucket string) ranger.Ranger {
	return &ObjectRanger{
		p:      p,
		o:      o,
		bucket: bucket,
	}
}

// Size returns object size.
func (ranger *ObjectRanger) Size() int64 {
	return ranger.o.System.ContentLength
}

// Range returns object read/close interface.
func (ranger *ObjectRanger) Range(ctx context.Context, offset, length int64) (_ io.ReadCloser, err error) {
	defer mon.Task()(&ctx)(&err)
	return ranger.p.DownloadObject(ctx, ranger.bucket, ranger.o.Key, &uplink.DownloadOptions{Offset: offset, Length: length})
}
