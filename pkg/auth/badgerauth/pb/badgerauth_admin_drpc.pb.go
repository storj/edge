// Code generated by protoc-gen-go-drpc. DO NOT EDIT.
// protoc-gen-go-drpc version: v0.0.33
// source: badgerauth_admin.proto

package pb

import (
	context "context"
	errors "errors"
	protojson "google.golang.org/protobuf/encoding/protojson"
	proto "google.golang.org/protobuf/proto"
	drpc "storj.io/drpc"
	drpcerr "storj.io/drpc/drpcerr"
)

type drpcEncoding_File_badgerauth_admin_proto struct{}

func (drpcEncoding_File_badgerauth_admin_proto) Marshal(msg drpc.Message) ([]byte, error) {
	return proto.Marshal(msg.(proto.Message))
}

func (drpcEncoding_File_badgerauth_admin_proto) MarshalAppend(buf []byte, msg drpc.Message) ([]byte, error) {
	return proto.MarshalOptions{}.MarshalAppend(buf, msg.(proto.Message))
}

func (drpcEncoding_File_badgerauth_admin_proto) Unmarshal(buf []byte, msg drpc.Message) error {
	return proto.Unmarshal(buf, msg.(proto.Message))
}

func (drpcEncoding_File_badgerauth_admin_proto) JSONMarshal(msg drpc.Message) ([]byte, error) {
	return protojson.Marshal(msg.(proto.Message))
}

func (drpcEncoding_File_badgerauth_admin_proto) JSONUnmarshal(buf []byte, msg drpc.Message) error {
	return protojson.Unmarshal(buf, msg.(proto.Message))
}

type DRPCAdminServiceClient interface {
	DRPCConn() drpc.Conn

	InvalidateRecord(ctx context.Context, in *InvalidateRecordRequest) (*InvalidateRecordResponse, error)
	UnpublishRecord(ctx context.Context, in *UnpublishRecordRequest) (*UnpublishRecordResponse, error)
	DeleteRecord(ctx context.Context, in *DeleteRecordRequest) (*DeleteRecordResponse, error)
}

type drpcAdminServiceClient struct {
	cc drpc.Conn
}

func NewDRPCAdminServiceClient(cc drpc.Conn) DRPCAdminServiceClient {
	return &drpcAdminServiceClient{cc}
}

func (c *drpcAdminServiceClient) DRPCConn() drpc.Conn { return c.cc }

func (c *drpcAdminServiceClient) InvalidateRecord(ctx context.Context, in *InvalidateRecordRequest) (*InvalidateRecordResponse, error) {
	out := new(InvalidateRecordResponse)
	err := c.cc.Invoke(ctx, "/badgerauth.AdminService/InvalidateRecord", drpcEncoding_File_badgerauth_admin_proto{}, in, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *drpcAdminServiceClient) UnpublishRecord(ctx context.Context, in *UnpublishRecordRequest) (*UnpublishRecordResponse, error) {
	out := new(UnpublishRecordResponse)
	err := c.cc.Invoke(ctx, "/badgerauth.AdminService/UnpublishRecord", drpcEncoding_File_badgerauth_admin_proto{}, in, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *drpcAdminServiceClient) DeleteRecord(ctx context.Context, in *DeleteRecordRequest) (*DeleteRecordResponse, error) {
	out := new(DeleteRecordResponse)
	err := c.cc.Invoke(ctx, "/badgerauth.AdminService/DeleteRecord", drpcEncoding_File_badgerauth_admin_proto{}, in, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

type DRPCAdminServiceServer interface {
	InvalidateRecord(context.Context, *InvalidateRecordRequest) (*InvalidateRecordResponse, error)
	UnpublishRecord(context.Context, *UnpublishRecordRequest) (*UnpublishRecordResponse, error)
	DeleteRecord(context.Context, *DeleteRecordRequest) (*DeleteRecordResponse, error)
}

type DRPCAdminServiceUnimplementedServer struct{}

func (s *DRPCAdminServiceUnimplementedServer) InvalidateRecord(context.Context, *InvalidateRecordRequest) (*InvalidateRecordResponse, error) {
	return nil, drpcerr.WithCode(errors.New("Unimplemented"), drpcerr.Unimplemented)
}

func (s *DRPCAdminServiceUnimplementedServer) UnpublishRecord(context.Context, *UnpublishRecordRequest) (*UnpublishRecordResponse, error) {
	return nil, drpcerr.WithCode(errors.New("Unimplemented"), drpcerr.Unimplemented)
}

func (s *DRPCAdminServiceUnimplementedServer) DeleteRecord(context.Context, *DeleteRecordRequest) (*DeleteRecordResponse, error) {
	return nil, drpcerr.WithCode(errors.New("Unimplemented"), drpcerr.Unimplemented)
}

type DRPCAdminServiceDescription struct{}

func (DRPCAdminServiceDescription) NumMethods() int { return 3 }

func (DRPCAdminServiceDescription) Method(n int) (string, drpc.Encoding, drpc.Receiver, interface{}, bool) {
	switch n {
	case 0:
		return "/badgerauth.AdminService/InvalidateRecord", drpcEncoding_File_badgerauth_admin_proto{},
			func(srv interface{}, ctx context.Context, in1, in2 interface{}) (drpc.Message, error) {
				return srv.(DRPCAdminServiceServer).
					InvalidateRecord(
						ctx,
						in1.(*InvalidateRecordRequest),
					)
			}, DRPCAdminServiceServer.InvalidateRecord, true
	case 1:
		return "/badgerauth.AdminService/UnpublishRecord", drpcEncoding_File_badgerauth_admin_proto{},
			func(srv interface{}, ctx context.Context, in1, in2 interface{}) (drpc.Message, error) {
				return srv.(DRPCAdminServiceServer).
					UnpublishRecord(
						ctx,
						in1.(*UnpublishRecordRequest),
					)
			}, DRPCAdminServiceServer.UnpublishRecord, true
	case 2:
		return "/badgerauth.AdminService/DeleteRecord", drpcEncoding_File_badgerauth_admin_proto{},
			func(srv interface{}, ctx context.Context, in1, in2 interface{}) (drpc.Message, error) {
				return srv.(DRPCAdminServiceServer).
					DeleteRecord(
						ctx,
						in1.(*DeleteRecordRequest),
					)
			}, DRPCAdminServiceServer.DeleteRecord, true
	default:
		return "", nil, nil, nil, false
	}
}

func DRPCRegisterAdminService(mux drpc.Mux, impl DRPCAdminServiceServer) error {
	return mux.Register(impl, DRPCAdminServiceDescription{})
}

type DRPCAdminService_InvalidateRecordStream interface {
	drpc.Stream
	SendAndClose(*InvalidateRecordResponse) error
}

type drpcAdminService_InvalidateRecordStream struct {
	drpc.Stream
}

func (x *drpcAdminService_InvalidateRecordStream) SendAndClose(m *InvalidateRecordResponse) error {
	if err := x.MsgSend(m, drpcEncoding_File_badgerauth_admin_proto{}); err != nil {
		return err
	}
	return x.CloseSend()
}

type DRPCAdminService_UnpublishRecordStream interface {
	drpc.Stream
	SendAndClose(*UnpublishRecordResponse) error
}

type drpcAdminService_UnpublishRecordStream struct {
	drpc.Stream
}

func (x *drpcAdminService_UnpublishRecordStream) SendAndClose(m *UnpublishRecordResponse) error {
	if err := x.MsgSend(m, drpcEncoding_File_badgerauth_admin_proto{}); err != nil {
		return err
	}
	return x.CloseSend()
}

type DRPCAdminService_DeleteRecordStream interface {
	drpc.Stream
	SendAndClose(*DeleteRecordResponse) error
}

type drpcAdminService_DeleteRecordStream struct {
	drpc.Stream
}

func (x *drpcAdminService_DeleteRecordStream) SendAndClose(m *DeleteRecordResponse) error {
	if err := x.MsgSend(m, drpcEncoding_File_badgerauth_admin_proto{}); err != nil {
		return err
	}
	return x.CloseSend()
}
