// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package minio

import (
	"io/ioutil"
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
		Body:       ioutil.NopCloser(strings.NewReader(`{"result":true}`)),
	}, nil
}

// StartMinio starts up Minio directly without its normal configuration process.
func StartMinio(authStore, gatewayLayer cmd.ObjectLayer, secureConn bool) {
	// wire up domain names for Minio
	// TODO (wthorp): can we set globalDomainNames directly instead?
	HandleCommonEnvVars()

	// make Minio not use random ETags
	GlobalCLIContext.Quiet = true
	GlobalCLIContext.StrictS3Compat = true
	GlobalIsSSL = secureConn

	// wire up object layer
	// TODO (wthorp): can we set globalObjectAPI directly instead?
	SetObjectLayer(gatewayLayer)

	// wire up Auth layer
	iamSys := cmd.NewIAMSys()
	iamSys.InitStore(authStore)
	GlobalIAMSys = iamSys

	// force globalIAMSys.IsAllowed() to always return true
	GlobalPolicyOPA = opa.New(opa.Args{URL: &xnet.URL{Scheme: "http"}, AuthToken: " ", Transport: allowAllOPA{}, CloseRespFn: xhttp.DrainBody})

	GlobalIsGateway = true

	GlobalBucketQuotaSys = cmd.NewBucketQuotaSys()

	// GlobalNotificationSys (minio/cmd.globalNotificationSys) can be left as a
	// global and have passed endpoints as nil because all its methods do
	// nothing when it's zero-valued. We don't care because we don't use it.
	// MinIO also doesn't initialise it for gateways except for the NAS gateway.
	GlobalNotificationSys = cmd.NewNotificationSys(nil)
}
