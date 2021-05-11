// Copyright (c) 2015-2021 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// This code is a derivative work.
// Derived changes Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package minio

import (
	"context"
	"net/http"
	"net/url"
	_ "unsafe" // for go:linkname

	"github.com/gorilla/mux"
	"github.com/storj/minio/cmd"
)

//  WriteErrorResponse exposes minio's cmd.writeErrorResponse
//
//nolint: golint
//go:linkname WriteErrorResponse github.com/storj/minio/cmd.writeErrorResponse
func WriteErrorResponse(ctx context.Context, w http.ResponseWriter, err cmd.APIError, reqURL *url.URL)

//  WriteErrorResponseString exposes minio's cmd.writeErrorResponseString
//
//nolint: golint
//go:linkname WriteErrorResponseString github.com/storj/minio/cmd.writeErrorResponseString
func WriteErrorResponseString(ctx context.Context, w http.ResponseWriter, err cmd.APIError, reqURL *url.URL)

// GetAPIError exposes minio's cmd.getAPIError
//
//nolint: golint
//go:linkname GetAPIError github.com/storj/minio/cmd.getAPIError
func GetAPIError(code cmd.APIErrorCode) cmd.APIError

// ToAPIErrorCode exposes minio's cmd.toAPIErrorCode
//
//nolint: golint
//go:linkname ToAPIErrorCode github.com/storj/minio/cmd.toAPIErrorCode
func ToAPIErrorCode(ctx context.Context, err error) (apiErr cmd.APIErrorCode)

// SetObjectLayer exposes minio's cmd.setObjectLayer
//
//nolint: golint
//go:linkname SetObjectLayer github.com/storj/minio/cmd.setObjectLayer
func SetObjectLayer(o cmd.ObjectLayer)

// HandleCommonEnvVars exposes minio's cmd.handleCommonEnvVars
//
//nolint: golint
//go:linkname HandleCommonEnvVars github.com/storj/minio/cmd.handleCommonEnvVars
func HandleCommonEnvVars()

// CorsHandler exposes minio's cmd.corsHandler
//
//nolint: golint
//go:linkname CorsHandler github.com/storj/minio/cmd.corsHandler
func CorsHandler(handler http.Handler) http.Handler

// TODO: This function will be necessary when we update Minio.
// // RejectUnsupportedAPIs exposes minio's cmd.rejectUnsupportedAPIs
// //
// //nolint: golint
// //go:linkname RejectUnsupportedAPIs github.com/storj/minio/cmd.rejectUnsupportedAPIs
// func RejectUnsupportedAPIs(router *mux.Router)

// GlobalHandlers exposes minio's cmd.globalHandlers
//
//nolint: golint
//go:linkname GlobalHandlers github.com/storj/minio/cmd.globalHandlers
var GlobalHandlers []mux.MiddlewareFunc

// GlobalCLIContext exposes minio's cmd.globalCLIContext
//
//nolint: golint
//go:linkname GlobalCLIContext github.com/storj/minio/cmd.globalCLIContext
var GlobalCLIContext = struct {
	JSON           bool
	Quiet          bool
	Anonymous      bool
	Addr           string
	StrictS3Compat bool
}{}

// GlobalIAMSys exposes minio's cmd.globalIAMSys
//
//nolint: golint
//go:linkname GlobalIAMSys github.com/storj/minio/cmd.globalIAMSys
var GlobalIAMSys *cmd.IAMSys
