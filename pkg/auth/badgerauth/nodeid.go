// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauth

// NodeID is a unique id for BadgerDB node.
type NodeID []byte

// SetBytes sets the node id from bytes.
func (id *NodeID) SetBytes(v []byte) error {
	*id = append(NodeID{}, v...)
	return nil
}

// Bytes returns the bytes for nodeID.
func (id NodeID) Bytes() []byte { return id[:] }
