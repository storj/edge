// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package minio

import (
	"context"
	"net/http"
	"net/url"
	_ "unsafe" // for go:linkname

	"github.com/storj/minio/cmd"
)

//  WriteErrorResponse exposes minio's cmd.writeErrorResponse
//
//nolint: golint
//go:linkname WriteErrorResponse github.com/storj/minio/cmd.writeErrorResponse
func WriteErrorResponse(ctx context.Context, w http.ResponseWriter, err cmd.APIError, reqURL *url.URL)

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
