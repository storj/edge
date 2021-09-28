// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package minio

import (
	"context"
	"net/http"
	"net/url"
	_ "unsafe" // for go:linkname

	"github.com/gorilla/mux"

	"storj.io/minio/cmd"
	"storj.io/minio/cmd/config/policy/opa"
)

// GlobalBucketQuotaSys exposes minio's cmd.globalBucketQuotaSys.
//
//nolint: golint
//go:linkname GlobalBucketQuotaSys storj.io/minio/cmd.globalBucketQuotaSys
var GlobalBucketQuotaSys *cmd.BucketQuotaSys

// GlobalCLIContext exposes minio's cmd.globalCLIContext.
//
//nolint: golint
//go:linkname GlobalCLIContext storj.io/minio/cmd.globalCLIContext
var GlobalCLIContext = struct {
	JSON, Quiet    bool
	Anonymous      bool
	Addr           string
	StrictS3Compat bool
}{}

// GlobalHandlers exposes minio's cmd.globalHandlers.
//
//nolint: golint
//go:linkname GlobalHandlers storj.io/minio/cmd.globalHandlers
var GlobalHandlers []mux.MiddlewareFunc

// GlobalIAMSys exposes minio's cmd.globalIAMSys.
//
//nolint: golint
//go:linkname GlobalIAMSys storj.io/minio/cmd.globalIAMSys
var GlobalIAMSys *cmd.IAMSys

// GlobalIsGateway exposes minio's cmd.globalIsGateway.
//
//nolint: golint
//go:linkname GlobalIsGateway storj.io/minio/cmd.globalIsGateway
var GlobalIsGateway bool

// GlobalNotificationSys exposes minio's cmd.globalNotificationSys.
//
//nolint: golint
//go:linkname GlobalNotificationSys storj.io/minio/cmd.globalNotificationSys
var GlobalNotificationSys *cmd.NotificationSys

// GlobalPolicyOPA exposes minio's cmd.globalPolicyOPA.
//
//nolint: golint
//go:linkname GlobalPolicyOPA storj.io/minio/cmd.globalPolicyOPA
var GlobalPolicyOPA *opa.Opa

// GlobalIsSSL exposes minio's cmd.globalIsSSL
//
//nolint: golint
//go:linkname GlobalIsSSL github.com/minio/minio/cmd.globalIsSSL
var GlobalIsSSL bool

// GetAPIError exposes minio's cmd.getAPIError.
//
//nolint: golint
//go:linkname GetAPIError storj.io/minio/cmd.getAPIError
func GetAPIError(code cmd.APIErrorCode) cmd.APIError

// HandleCommonEnvVars exposes minio's cmd.handleCommonEnvVars.
//
//nolint: golint
//go:linkname HandleCommonEnvVars storj.io/minio/cmd.handleCommonEnvVars
func HandleCommonEnvVars()

// RegisterAPIRouter exposes minio's cmd.registerAPIRouter.
//
//nolint: golint
//go:linkname RegisterAPIRouter storj.io/minio/cmd.registerAPIRouter
func RegisterAPIRouter(router *mux.Router)

// RegisterHealthCheckRouter exposes minio's cmd.registerHealthCheckRouter.
//
//nolint: golint
//go:linkname RegisterHealthCheckRouter storj.io/minio/cmd.registerHealthCheckRouter
func RegisterHealthCheckRouter(router *mux.Router)

// RegisterMetricsRouter exposes minio's cmd.registerMetricsRouter.
//
//nolint: golint
//go:linkname RegisterMetricsRouter storj.io/minio/cmd.registerMetricsRouter
func RegisterMetricsRouter(router *mux.Router)

// SetObjectLayer exposes minio's cmd.setObjectLayer.
//
//nolint: golint
//go:linkname SetObjectLayer storj.io/minio/cmd.setObjectLayer
func SetObjectLayer(o cmd.ObjectLayer)

// WriteErrorResponse exposes minio's cmd.writeErrorResponse.
//
//nolint: golint
//go:linkname WriteErrorResponse storj.io/minio/cmd.writeErrorResponse
func WriteErrorResponse(ctx context.Context, w http.ResponseWriter, err cmd.APIError, reqURL *url.URL, browser bool)
