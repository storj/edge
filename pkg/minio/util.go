// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package minio

import (
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"
	"unsafe"

	"github.com/minio/minio/cmd"
	"github.com/minio/minio/cmd/config/policy/opa"
	xhttp "github.com/minio/minio/cmd/http"
	xnet "github.com/minio/minio/pkg/net"
)

type allowAllOPA struct{}

func (s allowAllOPA) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       ioutil.NopCloser(strings.NewReader(`{"result":true}`)),
	}, nil
}

func setUnexportedField(field reflect.Value, value interface{}) {
	reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Set(reflect.ValueOf(value))
}

// StartMinio starts up Minio directly without its normal configuration process.
func StartMinio(address, authURL, authToken string, gatewayLayer cmd.ObjectLayer) {
	// wire up domain names for Minio
	// TODO (wthorp): can we set globalDomainNames directly instead?
	HandleCommonEnvVars()

	// make Minio not use random ETags
	GlobalCLIContext.Quiet = true
	GlobalCLIContext.Addr = address
	GlobalCLIContext.StrictS3Compat = true

	// wire up Auth
	store := cmd.NewIAMStorjAuthStore(gatewayLayer, authURL, authToken)
	// TODO (wthorp): can we set globalObjectAPI directly instead?
	SetObjectLayer(gatewayLayer)
	iamSys := cmd.NewIAMSys()
	rs := reflect.ValueOf(iamSys).Elem()
	setUnexportedField(rs.Field(1), cmd.UsersSysType("StorjAuthSys"))
	setUnexportedField(rs.Field(8), store)
	GlobalIAMSys = iamSys

	// force globalIAMSys.IsAllowed() to always return true
	GlobalPolicyOPA = opa.New(opa.Args{URL: &xnet.URL{Scheme: "http"}, AuthToken: " ", Transport: allowAllOPA{}, CloseRespFn: xhttp.DrainBody})

	GlobalIsGateway = true
	GlobalNotificationSys = cmd.NewNotificationSys(GlobalEndpoints)
	GlobalBucketQuotaSys = cmd.NewBucketQuotaSys()
}
