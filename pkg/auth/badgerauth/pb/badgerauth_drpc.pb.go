// Code generated by protoc-gen-go-drpc. DO NOT EDIT.
// protoc-gen-go-drpc version: v0.0.34
// source: badgerauth.proto

package pb

import (
	context "context"
	errors "errors"
	protojson "google.golang.org/protobuf/encoding/protojson"
	proto "google.golang.org/protobuf/proto"
	drpc "storj.io/drpc"
	drpcerr "storj.io/drpc/drpcerr"
)

type drpcEncoding_File_badgerauth_proto struct{}

func (drpcEncoding_File_badgerauth_proto) Marshal(msg drpc.Message) ([]byte, error) {
	return proto.Marshal(msg.(proto.Message))
}

func (drpcEncoding_File_badgerauth_proto) MarshalAppend(buf []byte, msg drpc.Message) ([]byte, error) {
	return proto.MarshalOptions{}.MarshalAppend(buf, msg.(proto.Message))
}

func (drpcEncoding_File_badgerauth_proto) Unmarshal(buf []byte, msg drpc.Message) error {
	return proto.Unmarshal(buf, msg.(proto.Message))
}

func (drpcEncoding_File_badgerauth_proto) JSONMarshal(msg drpc.Message) ([]byte, error) {
	return protojson.Marshal(msg.(proto.Message))
}

func (drpcEncoding_File_badgerauth_proto) JSONUnmarshal(buf []byte, msg drpc.Message) error {
	return protojson.Unmarshal(buf, msg.(proto.Message))
}

type DRPCReplicationServiceClient interface {
	DRPCConn() drpc.Conn

	Ping(ctx context.Context, in *PingRequest) (*PingResponse, error)
	Peek(ctx context.Context, in *PeekRequest) (*PeekResponse, error)
	Replicate(ctx context.Context, in *ReplicationRequest) (*ReplicationResponse, error)
}

type drpcReplicationServiceClient struct {
	cc drpc.Conn
}

func NewDRPCReplicationServiceClient(cc drpc.Conn) DRPCReplicationServiceClient {
	return &drpcReplicationServiceClient{cc}
}

func (c *drpcReplicationServiceClient) DRPCConn() drpc.Conn { return c.cc }

func (c *drpcReplicationServiceClient) Ping(ctx context.Context, in *PingRequest) (*PingResponse, error) {
	out := new(PingResponse)
	err := c.cc.Invoke(ctx, "/badgerauth.ReplicationService/Ping", drpcEncoding_File_badgerauth_proto{}, in, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *drpcReplicationServiceClient) Peek(ctx context.Context, in *PeekRequest) (*PeekResponse, error) {
	out := new(PeekResponse)
	err := c.cc.Invoke(ctx, "/badgerauth.ReplicationService/Peek", drpcEncoding_File_badgerauth_proto{}, in, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *drpcReplicationServiceClient) Replicate(ctx context.Context, in *ReplicationRequest) (*ReplicationResponse, error) {
	out := new(ReplicationResponse)
	err := c.cc.Invoke(ctx, "/badgerauth.ReplicationService/Replicate", drpcEncoding_File_badgerauth_proto{}, in, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

type DRPCReplicationServiceServer interface {
	Ping(context.Context, *PingRequest) (*PingResponse, error)
	Peek(context.Context, *PeekRequest) (*PeekResponse, error)
	Replicate(context.Context, *ReplicationRequest) (*ReplicationResponse, error)
}

type DRPCReplicationServiceUnimplementedServer struct{}

func (s *DRPCReplicationServiceUnimplementedServer) Ping(context.Context, *PingRequest) (*PingResponse, error) {
	return nil, drpcerr.WithCode(errors.New("Unimplemented"), drpcerr.Unimplemented)
}

func (s *DRPCReplicationServiceUnimplementedServer) Peek(context.Context, *PeekRequest) (*PeekResponse, error) {
	return nil, drpcerr.WithCode(errors.New("Unimplemented"), drpcerr.Unimplemented)
}

func (s *DRPCReplicationServiceUnimplementedServer) Replicate(context.Context, *ReplicationRequest) (*ReplicationResponse, error) {
	return nil, drpcerr.WithCode(errors.New("Unimplemented"), drpcerr.Unimplemented)
}

type DRPCReplicationServiceDescription struct{}

func (DRPCReplicationServiceDescription) NumMethods() int { return 3 }

func (DRPCReplicationServiceDescription) Method(n int) (string, drpc.Encoding, drpc.Receiver, interface{}, bool) {
	switch n {
	case 0:
		return "/badgerauth.ReplicationService/Ping", drpcEncoding_File_badgerauth_proto{},
			func(srv interface{}, ctx context.Context, in1, in2 interface{}) (drpc.Message, error) {
				return srv.(DRPCReplicationServiceServer).
					Ping(
						ctx,
						in1.(*PingRequest),
					)
			}, DRPCReplicationServiceServer.Ping, true
	case 1:
		return "/badgerauth.ReplicationService/Peek", drpcEncoding_File_badgerauth_proto{},
			func(srv interface{}, ctx context.Context, in1, in2 interface{}) (drpc.Message, error) {
				return srv.(DRPCReplicationServiceServer).
					Peek(
						ctx,
						in1.(*PeekRequest),
					)
			}, DRPCReplicationServiceServer.Peek, true
	case 2:
		return "/badgerauth.ReplicationService/Replicate", drpcEncoding_File_badgerauth_proto{},
			func(srv interface{}, ctx context.Context, in1, in2 interface{}) (drpc.Message, error) {
				return srv.(DRPCReplicationServiceServer).
					Replicate(
						ctx,
						in1.(*ReplicationRequest),
					)
			}, DRPCReplicationServiceServer.Replicate, true
	default:
		return "", nil, nil, nil, false
	}
}

func DRPCRegisterReplicationService(mux drpc.Mux, impl DRPCReplicationServiceServer) error {
	return mux.Register(impl, DRPCReplicationServiceDescription{})
}

type DRPCReplicationService_PingStream interface {
	drpc.Stream
	SendAndClose(*PingResponse) error
}

type drpcReplicationService_PingStream struct {
	drpc.Stream
}

func (x *drpcReplicationService_PingStream) SendAndClose(m *PingResponse) error {
	if err := x.MsgSend(m, drpcEncoding_File_badgerauth_proto{}); err != nil {
		return err
	}
	return x.CloseSend()
}

type DRPCReplicationService_PeekStream interface {
	drpc.Stream
	SendAndClose(*PeekResponse) error
}

type drpcReplicationService_PeekStream struct {
	drpc.Stream
}

func (x *drpcReplicationService_PeekStream) SendAndClose(m *PeekResponse) error {
	if err := x.MsgSend(m, drpcEncoding_File_badgerauth_proto{}); err != nil {
		return err
	}
	return x.CloseSend()
}

type DRPCReplicationService_ReplicateStream interface {
	drpc.Stream
	SendAndClose(*ReplicationResponse) error
}

type drpcReplicationService_ReplicateStream struct {
	drpc.Stream
}

func (x *drpcReplicationService_ReplicateStream) SendAndClose(m *ReplicationResponse) error {
	if err := x.MsgSend(m, drpcEncoding_File_badgerauth_proto{}); err != nil {
		return err
	}
	return x.CloseSend()
}
