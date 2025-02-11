// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package simplegateway

// Config is configuration for gateway.
type Config struct {
	Address string `help:"Address to listen on" default:"127.0.0.1:7777"`
	DataDir string `help:"Path to data storage"`
}

// MinioConfig is config for minio.
type MinioConfig struct {
	AccessKey string `help:"Access Key to use"`
	SecretKey string `help:"Secret Key to use"`
	ConfigDir string `help:"Minio generic server config path" default:"$CONFDIR/minio"`
}
