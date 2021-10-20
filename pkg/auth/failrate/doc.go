// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

// Package failrate provides a rate limiter for handling a limiter per key on
// failed operations.
//
// A key is unique string that identifies the entity that requests an operation
// to be rate-limited.
//
// After an operation is executed the caller must indicate to the limiter if it
// has succeeded or failed.
//
// When an operation fails, the rate limiter creates and register a limiter for
// the specified key if there isn't already a registered one.
// Subsequent operations (for the specified key) are checked through the limiter
// and canceling the counting to the limit if the operation succeeds.
//
// Successful operations don't make any change to the limit, while failed ones
// count to the limit.
//
// Because it is impossible to know if an operation will succeed or fail, the
// request of an operation call is refused if the limiter has reached the
// allowance, despite what it is going to be its result because that's the
// purpose of the limiter (i.e. Limit the number of call to an operation).
//
// Rate limiter are unregistered and deleted on least recently used fashion or
// when an operation request over a specific key succeed and its registered
// limit reaches its initial state (i.e. Limiter has its full allowance).
package failrate
