// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package simplegateway

import "storj.io/common/memory"

// Config is configuration for gateway.
type Config struct {
	Address       string      `help:"Address to listen on" default:"127.0.0.1:7777"`
	DataDir       string      `help:"Path to data storage"`
	MaxObjectSize memory.Size `help:"Maximum object size that can be uploaded" default:"1MiB"`
}

// MinioConfig is config for minio.
type MinioConfig struct {
	AccessKey string `help:"Access Key to use"`
	SecretKey string `help:"Secret Key to use"`
	ConfigDir string `help:"Minio generic server config path" default:"$CONFDIR/minio"`
}
