// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauth

import (
	"context"
	"time"

	"storj.io/common/rpc/rpcstatus"
	"storj.io/gateway-mt/pkg/auth/authdb"
	"storj.io/gateway-mt/pkg/auth/badgerauth/pb"
)

// Admin represents a service that allows managing database records directly.
type Admin struct {
	db *DB
}

var _ pb.DRPCAdminServiceServer = (*Admin)(nil)

// NewAdmin creates a new instance of Admin.
func NewAdmin(db *DB) *Admin {
	return &Admin{db: db}
}

// GetRecord gets a database record.
func (admin *Admin) GetRecord(ctx context.Context, req *pb.GetRecordRequest) (_ *pb.GetRecordResponse, err error) {
	defer mon.Task(admin.db.eventTags(adminGet)...)(&ctx)(&err)

	var resp pb.GetRecordResponse

	var keyHash authdb.KeyHash
	if err = keyHash.SetBytes(req.Key); err != nil {
		return nil, errToRPCStatusErr(err)
	}

	resp.Record, err = admin.db.lookupRecord(ctx, keyHash)
	if err != nil {
		return nil, errToRPCStatusErr(err)
	}

	return &resp, nil
}

// InvalidateRecord invalidates a record.
func (admin *Admin) InvalidateRecord(ctx context.Context, req *pb.InvalidateRecordRequest) (_ *pb.InvalidateRecordResponse, err error) {
	defer mon.Task(admin.db.eventTags(adminInvalidate)...)(&ctx)(&err)

	var resp pb.InvalidateRecordResponse

	if req.Reason == "" {
		return nil, rpcstatus.Error(rpcstatus.InvalidArgument, "missing reason")
	}

	var keyHash authdb.KeyHash
	if err = keyHash.SetBytes(req.Key); err != nil {
		return nil, errToRPCStatusErr(err)
	}

	return &resp, errToRPCStatusErr(admin.db.updateRecord(ctx, keyHash, func(record *pb.Record) {
		record.InvalidatedAtUnix = time.Now().Unix()
		record.InvalidationReason = req.Reason
	}))
}

// UnpublishRecord unpublishes a record.
func (admin *Admin) UnpublishRecord(ctx context.Context, req *pb.UnpublishRecordRequest) (_ *pb.UnpublishRecordResponse, err error) {
	defer mon.Task(admin.db.eventTags(adminUnpublish)...)(&ctx)(&err)

	var resp pb.UnpublishRecordResponse

	var keyHash authdb.KeyHash
	if err = keyHash.SetBytes(req.Key); err != nil {
		return nil, errToRPCStatusErr(err)
	}

	return &resp, errToRPCStatusErr(admin.db.updateRecord(ctx, keyHash, func(record *pb.Record) {
		record.Public = false
	}))
}

// DeleteRecord deletes a database record.
func (admin *Admin) DeleteRecord(ctx context.Context, req *pb.DeleteRecordRequest) (_ *pb.DeleteRecordResponse, err error) {
	defer mon.Task(admin.db.eventTags(adminDelete)...)(&ctx)(&err)

	var resp pb.DeleteRecordResponse

	var keyHash authdb.KeyHash
	if err = keyHash.SetBytes(req.Key); err != nil {
		return nil, errToRPCStatusErr(err)
	}

	return &resp, errToRPCStatusErr(admin.db.deleteRecord(ctx, keyHash))
}
