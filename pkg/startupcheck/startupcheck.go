// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package startupcheck

import (
	"context"
	"time"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"

	"storj.io/common/errs2"
	"storj.io/common/identity"
	"storj.io/common/peertls/tlsopts"
	"storj.io/common/rpc"
	"storj.io/common/rpc/rpcpool"
	"storj.io/common/storj"
	"storj.io/gateway-mt/pkg/nodelist"
)

const defaultTimeout = 60 * time.Second

var (
	mon = monkit.Package()

	// Error is a class of startup check errors.
	Error = errs.Class("startup check")

	_ Logger = (*wrappedLogger)(nil)
)

// Logger is for logging startup checks.
type Logger interface {
	Infof(template string, args ...interface{})
	Errorf(template string, args ...interface{})
}

type wrappedLogger struct {
	logger Logger
}

func (w *wrappedLogger) Infof(template string, args ...interface{}) {
	if w.logger != nil {
		w.logger.Infof(template, args...)
	}
}

func (w *wrappedLogger) Errorf(template string, args ...interface{}) {
	if w.logger != nil {
		w.logger.Errorf(template, args...)
	}
}

// NodeURLCheck checks for node URL connectivity.
type NodeURLCheck struct {
	nodeURLs []string
	logger   Logger
	timeout  time.Duration
	dialer   *rpc.Dialer
}

// NodeURLCheckConfig configures NodeURLCheck.
type NodeURLCheckConfig struct {
	// NodeURLs is a list of node URLs that we must be able to establish a
	// connection to. It can be made up of any of the following:
	//   - A URL that responds with node IDs newline separated.
	//     e.g. https://www.storj.io/dcs-satellites
	//   - A local file path containing node IDs newline separated.
	//     e.g. /path/to/my/satellites.txt
	//   - Individual satellite node URLs.
	//     e.g. 12EayRS2V1kEsWESU9QMRseFhdxYxKicsiFmxrsLZHeLUtdps3S@us1.storj.io:7777
	NodeURLs []string

	// Logger is an optional logger to log check information.
	Logger Logger

	// Timeout is how long checks can run before canceling.
	Timeout time.Duration

	// IdentityConfig is used for node verification. If not given, a new identity
	// with low difficulty is generated instead.
	IdentityConfig identity.Config
}

// NewNodeURLCheck returns a new NodeURLCheck.
func NewNodeURLCheck(config NodeURLCheckConfig) (c *NodeURLCheck, err error) {
	timeout := config.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}

	var ident *identity.FullIdentity
	if config.IdentityConfig.CertPath != "" && config.IdentityConfig.KeyPath != "" {
		ident, err = config.IdentityConfig.Load()
	} else {
		ident, err = identity.NewFullIdentity(context.Background(), identity.NewCAOptions{
			Difficulty:  0,
			Concurrency: 1,
		})
	}
	if err != nil {
		return nil, err
	}

	tlsOptions, err := tlsopts.NewOptions(ident, tlsopts.Config{
		UsePeerCAWhitelist: false,
		PeerIDVersions:     "0",
	}, nil)
	if err != nil {
		return nil, err
	}

	dialer := rpc.NewDefaultDialer(tlsOptions)
	// individual node dials can take as long as they want, but we still
	// impose a timeout across all dials in a check.
	dialer.DialTimeout = 0

	return &NodeURLCheck{
		nodeURLs: config.NodeURLs,
		logger:   &wrappedLogger{logger: config.Logger},
		timeout:  timeout,
		dialer:   &dialer,
	}, nil
}

// Check runs the check.
func (c *NodeURLCheck) Check(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	nodeURLs, _, err := nodelist.Resolve(ctx, c.nodeURLs)
	if err != nil {
		return Error.Wrap(err)
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	var group errs2.Group

	for nodeURL := range nodeURLs {
		nodeURL := nodeURL
		group.Go(func() error {
			return c.check(ctx, nodeURL)
		})
	}

	return Error.Wrap(errs.Combine(group.Wait()...))
}

func (c *NodeURLCheck) check(ctx context.Context, nodeURL storj.NodeURL) (err error) {
	defer mon.Task()(&ctx)(&err)

	if nodeURL.Address == "" {
		c.logger.Errorf("node URL %q missing address", nodeURL.String())
		return nil
	}

	c.logger.Infof("checking %q", nodeURL.String())

	conn, err := c.dialer.DialNodeURL(rpcpool.WithForceDial(ctx), nodeURL)
	if err != nil {
		return err
	}

	return conn.Close()
}
