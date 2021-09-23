// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package minio

import (
	"context"
	"net/http"
	"net/url"
	_ "unsafe" // for go:linkname

	"github.com/gorilla/mux"
	"github.com/minio/minio/cmd"
	"github.com/minio/minio/cmd/config/policy/opa"
)

// CLIContext exposes a struct corresponding to minio's GlobalCLIContext.
type CLIContext struct {
	JSON           bool
	Quiet          bool
	Anonymous      bool
	Addr           string
	StrictS3Compat bool
}

// GlobalBucketQuotaSys exposes minio's cmd.globalBucketQuotaSys.
//
//nolint: golint
//go:linkname GlobalBucketQuotaSys github.com/minio/minio/cmd.globalBucketQuotaSys
var GlobalBucketQuotaSys *cmd.BucketQuotaSys

// GlobalCLIContext exposes minio's cmd.globalCLIContext.
//
//nolint: golint
//go:linkname GlobalCLIContext github.com/minio/minio/cmd.globalCLIContext
var GlobalCLIContext CLIContext

// GlobalEndpoints exposes minio's cmd.globalEndpoints.
//
//nolint: golint
//go:linkname GlobalEndpoints github.com/minio/minio/cmd.globalEndpoints
var GlobalEndpoints cmd.EndpointServerPools

// GlobalHandlers exposes minio's cmd.globalHandlers.
//
//nolint: golint
//go:linkname GlobalHandlers github.com/minio/minio/cmd.globalHandlers
var GlobalHandlers []mux.MiddlewareFunc

// GlobalIAMSys exposes minio's cmd.globalIAMSys.
//
//nolint: golint
//go:linkname GlobalIAMSys github.com/minio/minio/cmd.globalIAMSys
var GlobalIAMSys *cmd.IAMSys

// GlobalIsGateway exposes minio's cmd.globalIsGateway.
//
//nolint: golint
//go:linkname GlobalIsGateway github.com/minio/minio/cmd.globalIsGateway
var GlobalIsGateway bool

// GlobalNotificationSys exposes minio's cmd.globalNotificationSys.
//
//nolint: golint
//go:linkname GlobalNotificationSys github.com/minio/minio/cmd.globalNotificationSys
var GlobalNotificationSys *cmd.NotificationSys

// GlobalPolicyOPA exposes minio's cmd.globalPolicyOPA.
//
//nolint: golint
//go:linkname GlobalPolicyOPA github.com/minio/minio/cmd.globalPolicyOPA
var GlobalPolicyOPA *opa.Opa

// GetAPIError exposes minio's cmd.getAPIError.
//
//nolint: golint
//go:linkname GetAPIError github.com/minio/minio/cmd.getAPIError
func GetAPIError(code cmd.APIErrorCode) cmd.APIError

// HandleCommonEnvVars exposes minio's cmd.handleCommonEnvVars.
//
//nolint: golint
//go:linkname HandleCommonEnvVars github.com/minio/minio/cmd.handleCommonEnvVars
func HandleCommonEnvVars()

// RegisterAPIRouter exposes minio's cmd.registerAPIRouter.
//
//nolint: golint
//go:linkname RegisterAPIRouter github.com/minio/minio/cmd.registerAPIRouter
func RegisterAPIRouter(router *mux.Router)

// RegisterHealthCheckRouter exposes minio's cmd.registerHealthCheckRouter.
//
//nolint: golint
//go:linkname RegisterHealthCheckRouter github.com/minio/minio/cmd.registerHealthCheckRouter
func RegisterHealthCheckRouter(router *mux.Router)

// RegisterMetricsRouter exposes minio's cmd.registerMetricsRouter.
//
//nolint: golint
//go:linkname RegisterMetricsRouter github.com/minio/minio/cmd.registerMetricsRouter
func RegisterMetricsRouter(router *mux.Router)

// SetObjectLayer exposes minio's cmd.setObjectLayer.
//
//nolint: golint
//go:linkname SetObjectLayer github.com/minio/minio/cmd.setObjectLayer
func SetObjectLayer(o cmd.ObjectLayer)

// WriteErrorResponse exposes minio's cmd.writeErrorResponse.
//
//nolint: golint
//go:linkname WriteErrorResponse github.com/minio/minio/cmd.writeErrorResponse
func WriteErrorResponse(ctx context.Context, w http.ResponseWriter, err cmd.APIError, reqURL *url.URL, browser bool)
