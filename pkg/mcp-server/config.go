// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package mcpserver

import (
	"time"

	"storj.io/edge/pkg/authclient"
)

// Config configures the MCP server.
type Config struct {
	Address                 string        `help:"Address to serve HTTP requests" default:":20110"`
	AddressTLS              string        `help:"Address to serve TLS requests" default:":20111"`
	ProxyAddressTLS         string        `help:"Address to serve TLS PROXY protocol requests" default:":20112"`
	InsecureDisableTLS      bool          `help:"Listen using insecure connections only" releaseDefault:"false" devDefault:"true"`
	DomainName              string        `help:"Comma-separated domain suffixes to serve on" releaseDefault:"" devDefault:"localhost"`
	LinkSharingURL          string        `help:"LinkSharing URL for sharing links" default:"https://link.storjshare.io"`
	IdleTimeout             time.Duration `help:"Maximum time to wait for the next request" default:"60s"`
	ShutdownDelay           time.Duration `help:"Time to delay server shutdown while returning 503s on the health endpoint" devDefault:"1s" releaseDefault:"45s"`
	Auth                    authclient.Config
	SatelliteConnectionPool satelliteConnectionPoolConfig
	ConnectionPool          connectionPoolConfig
	CertMagic               certMagic
}

type certMagic struct {
	Enabled                 bool   `help:"use CertMagic to handle TLS certificates" default:"false"`
	KeyFile                 string `help:"path to service account key file (permissions to use Google's Cloud Storage, Certificate Manager Public CA and Cloud DNS)"`
	Project                 string `help:"a project where the Google Cloud DNS zone exists"`
	ChallengeOverrideDomain string `help:"domain to set the TXT record on, to delegate the challenge to a different domain"`
	Email                   string `help:"email address to use while creating an ACME account"`
	Staging                 bool   `help:"use staging CA endpoints" devDefault:"true" releaseDefault:"false"`
	Bucket                  string `help:"bucket to use for certificate storage"`
}

type connectionPoolConfig struct {
	Capacity       int           `help:"RPC connection pool capacity (non-satellite connections)" default:"100"`
	KeyCapacity    int           `help:"RPC connection pool limit per key (non-satellite connections)" default:"5"`
	IdleExpiration time.Duration `help:"RPC connection pool idle expiration (non-satellite connections)" default:"2m0s"`
	MaxLifetime    time.Duration `help:"RPC connection pool max lifetime of a connection (non-satellite connections)" default:"10m0s"`
}

type satelliteConnectionPoolConfig struct {
	Capacity       int           `help:"RPC connection pool capacity (satellite connections)" default:"200"`
	KeyCapacity    int           `help:"RPC connection pool limit per key (satellite connections)" default:"0"`
	IdleExpiration time.Duration `help:"RPC connection pool idle expiration (satellite connections)" default:"10m0s"`
	MaxLifetime    time.Duration `help:"RPC connection pool max lifetime of a connection (satellite connections)" default:"10m0s"`
}
