// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"time"

	"storj.io/common/memory"
	"storj.io/gateway-mt/pkg/authclient"
	"storj.io/gateway/miniogw"
)

// AddrConfig honestly only exists to preserve legacy CLI parameter naming.
type AddrConfig struct {
	Address    string `help:"Address to serve gateway on" default:"127.0.0.1:20010"`
	AddressTLS string `help:"Address to securely serve (TLS) gateway on" default:"127.0.0.1:20011"`
}

// Config determines how server listens for requests.
type Config struct {
	Server               AddrConfig
	CertDir              string        `help:"directory path to search for TLS certificates" default:"$CONFDIR/certs"`
	InsecureDisableTLS   bool          `help:"listen using insecure connections" releaseDefault:"false" devDefault:"true"`
	DomainName           string        `help:"comma-separated domain suffixes to serve on" releaseDefault:"" devDefault:"localhost"`
	CorsOrigins          string        `help:"list of domains (comma separated) other than the gateway's domain, from which a browser should permit loading resources requested from the gateway" default:"*"`
	EncodeInMemory       bool          `help:"tells libuplink to perform in-memory encoding on file upload" releaseDefault:"true" devDefault:"true"`
	ClientTrustedIPSList []string      `help:"list of clients IPs (without port and comma separated) which are trusted; usually used when the service run behinds gateways, load balancers, etc."`
	UseClientIPHeaders   bool          `help:"use the headers sent by the client to identify its IP. When true the list of IPs set by --client-trusted-ips-list, when not empty, is used" default:"true"`
	InsecureLogAll       bool          `help:"insecurely log all errors, paths, and headers" default:"false"`
	ConcurrentAllowed    uint          `help:"number of allowed concurrent uploads or downloads per macaroon head" default:"500"` // see S3 CLI's max_concurrent_requests
	ShutdownDelay        time.Duration `help:"time to delay server shutdown while returning 503s on the health endpoint" devDefault:"1s" releaseDefault:"45s"`

	Auth                    authclient.Config
	S3Compatibility         miniogw.S3CompatibilityConfig
	Client                  ClientConfig
	SatelliteConnectionpool SatelliteConnectionPoolConfig
	ConnectionPool          ConnectionPoolConfig
	CertMagic               certMagic
}

type certMagic struct {
	Enabled bool   `user:"true" help:"use CertMagic to handle TLS certificates" default:"false"`
	KeyFile string `user:"true" help:"path to service account key file (permissions to use Google's Cloud Storage, Certificate Manager Public CA and Cloud DNS)"`
	Project string `user:"true" help:"a project where the Google Cloud DNS zone exists"`
	Email   string `user:"true" help:"email address to use while creating an ACME account"`
	Staging bool   `user:"true" help:"use staging CA endpoints" devDefault:"true" releaseDefault:"false"`
	Bucket  string `user:"true" help:"bucket to use for certificate storage"`
}

// ConnectionPoolConfig is a config struct for configuring RPC connection pool
// options.
type ConnectionPoolConfig struct {
	Capacity       int           `help:"RPC connection pool capacity (non-satellite connections)" default:"100"`
	KeyCapacity    int           `help:"RPC connection pool limit per key (non-satellite connections)" default:"5"`
	IdleExpiration time.Duration `help:"RPC connection pool idle expiration (non-satellite connections)" default:"2m0s"`
}

// SatelliteConnectionPoolConfig is a config struct for configuring RPC connection pool of Satellite connections.
type SatelliteConnectionPoolConfig struct {
	Capacity       int           `help:"RPC connection pool capacity (satellite connections)" default:"200"`
	KeyCapacity    int           `help:"RPC connection pool limit per key (satellite connections)" default:"0"`
	IdleExpiration time.Duration `help:"RPC connection pool idle expiration (satellite connections)" default:"10m0s"`
}

// ClientConfig is a configuration struct for the uplink that controls how to
// talk to the rest of the network.
//
// MaximumBufferSize has a default of 304 kB, as this seems to be around the
// maximum buffer size drpcstream.(*Stream).MsgSend allocates when it's used
// from libuplink from Gateway-MT (see https://pprof.host/0w/). Deployments
// struggling with memory consumption problems should decrease the default.
type ClientConfig struct {
	DialTimeout       time.Duration `help:"timeout for dials" default:"10s"`
	MaximumBufferSize memory.Size   `help:"maximum buffer size for DRPC streams" default:"304kB"`
}
