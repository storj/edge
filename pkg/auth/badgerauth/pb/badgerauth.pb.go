// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        v4.25.1
// source: badgerauth.proto

package pb

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Record_State int32

const (
	Record_CREATED Record_State = 0
)

// Enum value maps for Record_State.
var (
	Record_State_name = map[int32]string{
		0: "CREATED",
	}
	Record_State_value = map[string]int32{
		"CREATED": 0,
	}
)

func (x Record_State) Enum() *Record_State {
	p := new(Record_State)
	*p = x
	return p
}

func (x Record_State) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Record_State) Descriptor() protoreflect.EnumDescriptor {
	return file_badgerauth_proto_enumTypes[0].Descriptor()
}

func (Record_State) Type() protoreflect.EnumType {
	return &file_badgerauth_proto_enumTypes[0]
}

func (x Record_State) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Record_State.Descriptor instead.
func (Record_State) EnumDescriptor() ([]byte, []int) {
	return file_badgerauth_proto_rawDescGZIP(), []int{0, 0}
}

type Record struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// record data
	CreatedAtUnix int64 `protobuf:"varint,1,opt,name=created_at_unix,json=createdAtUnix,proto3" json:"created_at_unix,omitempty"`
	Public        bool  `protobuf:"varint,2,opt,name=public,proto3" json:"public,omitempty"`
	// denormalized information from access grant
	SatelliteAddress string `protobuf:"bytes,3,opt,name=satellite_address,json=satelliteAddress,proto3" json:"satellite_address,omitempty"`
	PublicProjectId  []byte `protobuf:"bytes,11,opt,name=public_project_id,json=publicProjectId,proto3" json:"public_project_id,omitempty"`
	MacaroonHead     []byte `protobuf:"bytes,4,opt,name=macaroon_head,json=macaroonHead,proto3" json:"macaroon_head,omitempty"`
	ExpiresAtUnix    int64  `protobuf:"varint,5,opt,name=expires_at_unix,json=expiresAtUnix,proto3" json:"expires_at_unix,omitempty"`
	// sensitive data
	EncryptedSecretKey   []byte `protobuf:"bytes,6,opt,name=encrypted_secret_key,json=encryptedSecretKey,proto3" json:"encrypted_secret_key,omitempty"`
	EncryptedAccessGrant []byte `protobuf:"bytes,7,opt,name=encrypted_access_grant,json=encryptedAccessGrant,proto3" json:"encrypted_access_grant,omitempty"`
	// invalidation tracking
	InvalidationReason string `protobuf:"bytes,8,opt,name=invalidation_reason,json=invalidationReason,proto3" json:"invalidation_reason,omitempty"`
	InvalidatedAtUnix  int64  `protobuf:"varint,9,opt,name=invalidated_at_unix,json=invalidatedAtUnix,proto3" json:"invalidated_at_unix,omitempty"`
	// deprecated synchronization-related data
	State Record_State `protobuf:"varint,10,opt,name=state,proto3,enum=badgerauth.Record_State" json:"state,omitempty"`
}

func (x *Record) Reset() {
	*x = Record{}
	if protoimpl.UnsafeEnabled {
		mi := &file_badgerauth_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Record) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Record) ProtoMessage() {}

func (x *Record) ProtoReflect() protoreflect.Message {
	mi := &file_badgerauth_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Record.ProtoReflect.Descriptor instead.
func (*Record) Descriptor() ([]byte, []int) {
	return file_badgerauth_proto_rawDescGZIP(), []int{0}
}

func (x *Record) GetCreatedAtUnix() int64 {
	if x != nil {
		return x.CreatedAtUnix
	}
	return 0
}

func (x *Record) GetPublic() bool {
	if x != nil {
		return x.Public
	}
	return false
}

func (x *Record) GetSatelliteAddress() string {
	if x != nil {
		return x.SatelliteAddress
	}
	return ""
}

func (x *Record) GetPublicProjectId() []byte {
	if x != nil {
		return x.PublicProjectId
	}
	return nil
}

func (x *Record) GetMacaroonHead() []byte {
	if x != nil {
		return x.MacaroonHead
	}
	return nil
}

func (x *Record) GetExpiresAtUnix() int64 {
	if x != nil {
		return x.ExpiresAtUnix
	}
	return 0
}

func (x *Record) GetEncryptedSecretKey() []byte {
	if x != nil {
		return x.EncryptedSecretKey
	}
	return nil
}

func (x *Record) GetEncryptedAccessGrant() []byte {
	if x != nil {
		return x.EncryptedAccessGrant
	}
	return nil
}

func (x *Record) GetInvalidationReason() string {
	if x != nil {
		return x.InvalidationReason
	}
	return ""
}

func (x *Record) GetInvalidatedAtUnix() int64 {
	if x != nil {
		return x.InvalidatedAtUnix
	}
	return 0
}

func (x *Record) GetState() Record_State {
	if x != nil {
		return x.State
	}
	return Record_CREATED
}

var File_badgerauth_proto protoreflect.FileDescriptor

var file_badgerauth_proto_rawDesc = []byte{
	0x0a, 0x10, 0x62, 0x61, 0x64, 0x67, 0x65, 0x72, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x12, 0x0a, 0x62, 0x61, 0x64, 0x67, 0x65, 0x72, 0x61, 0x75, 0x74, 0x68, 0x22, 0xfd,
	0x03, 0x0a, 0x06, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x12, 0x26, 0x0a, 0x0f, 0x63, 0x72, 0x65,
	0x61, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x5f, 0x75, 0x6e, 0x69, 0x78, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x03, 0x52, 0x0d, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x55, 0x6e, 0x69,
	0x78, 0x12, 0x16, 0x0a, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x08, 0x52, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x12, 0x2b, 0x0a, 0x11, 0x73, 0x61, 0x74,
	0x65, 0x6c, 0x6c, 0x69, 0x74, 0x65, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x10, 0x73, 0x61, 0x74, 0x65, 0x6c, 0x6c, 0x69, 0x74, 0x65, 0x41,
	0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x2a, 0x0a, 0x11, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
	0x5f, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x0b, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x0f, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x50, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74,
	0x49, 0x64, 0x12, 0x23, 0x0a, 0x0d, 0x6d, 0x61, 0x63, 0x61, 0x72, 0x6f, 0x6f, 0x6e, 0x5f, 0x68,
	0x65, 0x61, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0c, 0x6d, 0x61, 0x63, 0x61, 0x72,
	0x6f, 0x6f, 0x6e, 0x48, 0x65, 0x61, 0x64, 0x12, 0x26, 0x0a, 0x0f, 0x65, 0x78, 0x70, 0x69, 0x72,
	0x65, 0x73, 0x5f, 0x61, 0x74, 0x5f, 0x75, 0x6e, 0x69, 0x78, 0x18, 0x05, 0x20, 0x01, 0x28, 0x03,
	0x52, 0x0d, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x73, 0x41, 0x74, 0x55, 0x6e, 0x69, 0x78, 0x12,
	0x30, 0x0a, 0x14, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x5f, 0x73, 0x65, 0x63,
	0x72, 0x65, 0x74, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x12, 0x65,
	0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x4b, 0x65,
	0x79, 0x12, 0x34, 0x0a, 0x16, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x5f, 0x61,
	0x63, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x67, 0x72, 0x61, 0x6e, 0x74, 0x18, 0x07, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x14, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x41, 0x63, 0x63, 0x65,
	0x73, 0x73, 0x47, 0x72, 0x61, 0x6e, 0x74, 0x12, 0x2f, 0x0a, 0x13, 0x69, 0x6e, 0x76, 0x61, 0x6c,
	0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x72, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x18, 0x08,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x12, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x12, 0x2e, 0x0a, 0x13, 0x69, 0x6e, 0x76, 0x61,
	0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x5f, 0x75, 0x6e, 0x69, 0x78, 0x18,
	0x09, 0x20, 0x01, 0x28, 0x03, 0x52, 0x11, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74,
	0x65, 0x64, 0x41, 0x74, 0x55, 0x6e, 0x69, 0x78, 0x12, 0x2e, 0x0a, 0x05, 0x73, 0x74, 0x61, 0x74,
	0x65, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x18, 0x2e, 0x62, 0x61, 0x64, 0x67, 0x65, 0x72,
	0x61, 0x75, 0x74, 0x68, 0x2e, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x2e, 0x53, 0x74, 0x61, 0x74,
	0x65, 0x52, 0x05, 0x73, 0x74, 0x61, 0x74, 0x65, 0x22, 0x14, 0x0a, 0x05, 0x53, 0x74, 0x61, 0x74,
	0x65, 0x12, 0x0b, 0x0a, 0x07, 0x43, 0x52, 0x45, 0x41, 0x54, 0x45, 0x44, 0x10, 0x00, 0x42, 0x26,
	0x5a, 0x24, 0x73, 0x74, 0x6f, 0x72, 0x6a, 0x2e, 0x69, 0x6f, 0x2f, 0x65, 0x64, 0x67, 0x65, 0x2f,
	0x70, 0x6b, 0x67, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x2f, 0x62, 0x61, 0x64, 0x67, 0x65, 0x72, 0x61,
	0x75, 0x74, 0x68, 0x2f, 0x70, 0x62, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_badgerauth_proto_rawDescOnce sync.Once
	file_badgerauth_proto_rawDescData = file_badgerauth_proto_rawDesc
)

func file_badgerauth_proto_rawDescGZIP() []byte {
	file_badgerauth_proto_rawDescOnce.Do(func() {
		file_badgerauth_proto_rawDescData = protoimpl.X.CompressGZIP(file_badgerauth_proto_rawDescData)
	})
	return file_badgerauth_proto_rawDescData
}

var file_badgerauth_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_badgerauth_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_badgerauth_proto_goTypes = []any{
	(Record_State)(0), // 0: badgerauth.Record.State
	(*Record)(nil),    // 1: badgerauth.Record
}
var file_badgerauth_proto_depIdxs = []int32{
	0, // 0: badgerauth.Record.state:type_name -> badgerauth.Record.State
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_badgerauth_proto_init() }
func file_badgerauth_proto_init() {
	if File_badgerauth_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_badgerauth_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*Record); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_badgerauth_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_badgerauth_proto_goTypes,
		DependencyIndexes: file_badgerauth_proto_depIdxs,
		EnumInfos:         file_badgerauth_proto_enumTypes,
		MessageInfos:      file_badgerauth_proto_msgTypes,
	}.Build()
	File_badgerauth_proto = out.File
	file_badgerauth_proto_rawDesc = nil
	file_badgerauth_proto_goTypes = nil
	file_badgerauth_proto_depIdxs = nil
}
