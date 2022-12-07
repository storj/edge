// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package minio

import (
	"io"
	"net/http"
	"strings"

	"storj.io/minio/cmd"
	"storj.io/minio/cmd/config/policy/opa"
	xhttp "storj.io/minio/cmd/http"
	xnet "storj.io/minio/pkg/net"
)

type allowAllOPA struct{}

func (s allowAllOPA) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"result":true}`)),
	}, nil
}

// StartMinio starts up Minio directly without its normal configuration process.
func StartMinio(secureConn bool) {
	// wire up domain names for Minio
	// TODO (wthorp): can we set globalDomainNames directly instead?
	cmd.HandleCommonEnvVars()

	// make Minio not use random ETags
	cmd.GlobalCLIContext.Quiet = true
	cmd.GlobalCLIContext.StrictS3Compat = true
	cmd.GlobalIsTLS = secureConn

	// wire up dummy object layer
	cmd.SetObjectLayer(&NotImplementedObjectStore{})

	// wire up Auth layer
	iamSys := cmd.NewIAMSys()
	iamSys.InitStore(&IAMAuthStore{})
	cmd.GlobalIAMSys = iamSys

	// force globalIAMSys.IsAllowed() to always return true
	cmd.GlobalPolicyOPA = opa.New(opa.Args{URL: &xnet.URL{Scheme: "http"}, AuthToken: " ", Transport: allowAllOPA{}, CloseRespFn: xhttp.DrainBody})

	cmd.GlobalIsGateway = true

	cmd.GlobalBucketQuotaSys = cmd.NewBucketQuotaSys()

	// GlobalNotificationSys (minio/cmd.globalNotificationSys) can be left as a
	// global and have passed endpoints as nil because all its methods do
	// nothing when it's zero-valued. We don't care because we don't use it.
	// MinIO also doesn't initialise it for gateways except for the NAS gateway.
	cmd.GlobalNotificationSys = cmd.NewNotificationSys(nil)
}
