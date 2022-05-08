// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package pb

import (
	"google.golang.org/protobuf/proto"
)

// Unmarshal is an alias for proto.Unmarshal.
func Unmarshal(b []byte, m proto.Message) error {
	return proto.Unmarshal(b, m)
}

// Marshal is an alias for proto.Marshal.
func Marshal(m proto.Message) ([]byte, error) {
	return proto.Marshal(m)
}

// Equal is an alias for proto.Equal.
func Equal(x, y proto.Message) bool {
	return proto.Equal(x, y)
}
