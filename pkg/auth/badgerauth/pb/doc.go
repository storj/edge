// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

// Package pb includes protobufs for the badgerauth package.
package pb

//go:generate protoc --go_out=paths=source_relative:. --go-drpc_out=paths=source_relative:. badgerauth.proto
//go:generate protoc --go_out=paths=source_relative:. --go-drpc_out=paths=source_relative:. badgerauth_admin.proto
