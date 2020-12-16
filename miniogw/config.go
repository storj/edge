// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package miniogw

import "storj.io/common/storj"

// MinioConfig is a configuration struct that keeps details about starting Minio.
type MinioConfig struct {
	Dir string `help:"Minio generic server config path" default:"$CONFDIR/minio"`
}

// ServerConfig determines how minio listens for requests.
type ServerConfig struct {
	Address string `help:"address to serve S3 api over" default:"127.0.0.1:7777" basic-help:"true"`
}

// RemoveNodeIDs removes the nodeIDs from a list of valid node URLs. This can
// be called prior to NewDatabase to prepare allowed satellite addresses.
func RemoveNodeIDs(ss []string) (p []string, err error) {
	for _, s := range ss {
		url, err := storj.ParseNodeURL(s)
		if err != nil {
			return nil, err
		}
		p = append(p, url.Address)
	}
	return p, nil
}
