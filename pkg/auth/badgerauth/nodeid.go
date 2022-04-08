// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauth

import "github.com/zeebo/errs"

// NodeIDError is a class of id errors.
var NodeIDError = errs.Class("node ID")

// NodeID is a unique id for BadgerDB node.
type NodeID [32]byte

// SetBytes sets the node id from bytes.
func (id *NodeID) SetBytes(v []byte) error {
	if len(v) > len(NodeID{}) {
		return NodeIDError.New("v exceeds the acceptable length")
	}
	copy(id[:], v)
	return nil
}

// Bytes returns the bytes for nodeID.
func (id NodeID) Bytes() []byte { return id[:] }
