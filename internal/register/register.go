// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package register

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/zeebo/errs"

	"storj.io/common/pb"
	"storj.io/common/rpc"
)

// Error is the default error class for the register package.
var Error = errs.Class("register")

// TODO(artur): every time someone needs to contact authservice, they create new
// request/response types because we never exported them. Maybe we should even
// export functions that prepare a request to authservice? Maybe
// `pb.EdgeRegisterAccess...` types should be used? Otherwise, someone makes a
// typo in those places somewhere, and the world will perish in flames forever.

// Credentials represents authservice's response.
type Credentials struct {
	AccessKeyID string `json:"access_key_id"`
	SecretKey   string `json:"secret_key"`
	Endpoint    string `json:"endpoint"`
}

func (c Credentials) String() string {
	return fmt.Sprintf("Access Key ID: %s\nSecret Access Key: %s\nEndpoint: %s",
		c.AccessKeyID, c.SecretKey, c.Endpoint)
}

// Access registers access at authservice at authAddr.
func Access(ctx context.Context, authAddr, access string, public bool) (Credentials, error) {
	u, err := url.Parse(authAddr)
	if err != nil {
		return Credentials{}, Error.Wrap(err)
	}
	if u.Scheme == "drpc" || u.Scheme == "drpcs" {
		return registerDRPC(ctx, u.Host, u.Scheme == "drpcs", access, public)
	}
	u.Path = "/v1/access"
	return registerHTTP(ctx, u.String(), access, public)
}

func registerDRPC(ctx context.Context, addr string, secure bool, access string, public bool) (Credentials, error) {
	d := rpc.NewDefaultDialer(nil)
	//lint:ignore SA1019 deprecated okay,
	//nolint:staticcheck // deprecated okay.
	c := rpc.NewDefaultTCPConnector(nil)
	c.SetSendDRPCMuxHeader(false) // TODO(artur): this is frustrating. There has to be a way to avoid this.
	d.Connector = c

	var (
		conn *rpc.Conn
		err  error
	)
	if secure {
		conn, err = d.DialAddressHostnameVerification(ctx, addr)
	} else {
		conn, err = d.DialAddressUnencrypted(ctx, addr)
	}
	if err != nil {
		return Credentials{}, Error.Wrap(err)
	}
	defer func() { _ = conn.Close() }()

	req := &pb.EdgeRegisterAccessRequest{
		AccessGrant: access,
		Public:      public,
	}
	res, err := pb.NewDRPCEdgeAuthClient(conn).RegisterAccess(ctx, req)
	if err != nil {
		return Credentials{}, Error.Wrap(err)
	}

	return Credentials{
		AccessKeyID: res.AccessKeyId,
		SecretKey:   res.SecretKey,
		Endpoint:    res.Endpoint,
	}, nil
}

func registerHTTP(ctx context.Context, adrr, access string, public bool) (Credentials, error) {
	payload := struct {
		AccessGrant string `json:"access_grant"`
		Public      bool   `json:"public"`
	}{
		AccessGrant: access,
		Public:      public,
	}

	var ret Credentials

	buf := bytes.NewBuffer(nil)
	if err := json.NewEncoder(buf).Encode(payload); err != nil {
		return ret, Error.Wrap(err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, adrr, buf)
	if err != nil {
		return ret, Error.Wrap(err)
	}
	res, err := (&http.Client{}).Do(req)
	if err != nil {
		return ret, Error.Wrap(err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		return ret, Error.New("non-ok status (%s)", res.Status)
	}

	return ret, json.NewDecoder(res.Body).Decode(&ret)
}
