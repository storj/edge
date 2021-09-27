// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package server

// Config determines how server listens for requests.
type Config struct {
	Address string `help:"Address to serve gateway on" default:"127.0.0.1:7777"`
	Dir     string `help:"Minio generic server config path" default:"$CONFDIR/minio"`
}
