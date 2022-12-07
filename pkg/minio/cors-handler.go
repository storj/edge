// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

/*
 * MinIO Cloud Storage, (C) 2016-2020 MinIO, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package minio

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rs/cors"

	"storj.io/minio/cmd"
	xhttp "storj.io/minio/cmd/http"
	"storj.io/minio/cmd/logger"
	"storj.io/minio/pkg/wildcard"
)

// CorsHandler handler for CORS (Cross Origin Resource Sharing).
func CorsHandler(allowedOrigins []string) mux.MiddlewareFunc {
	return func(handler http.Handler) http.Handler {
		commonS3Headers := []string{
			xhttp.Date,
			xhttp.ETag,
			xhttp.ServerInfo,
			xhttp.Connection,
			xhttp.AcceptRanges,
			xhttp.ContentRange,
			xhttp.ContentEncoding,
			xhttp.ContentLength,
			xhttp.ContentType,
			xhttp.ContentDisposition,
			xhttp.LastModified,
			xhttp.ContentLanguage,
			xhttp.CacheControl,
			xhttp.RetryAfter,
			xhttp.AmzBucketRegion,
			xhttp.Expires,
			"X-Amz*",
			"x-amz*",
			"*",
		}

		return cors.New(cors.Options{
			AllowOriginFunc: func(origin string) bool {
				for _, allowedOrigin := range allowedOrigins {
					if wildcard.MatchSimple(allowedOrigin, origin) {
						return true
					}
				}
				return false
			},
			AllowedMethods: []string{
				http.MethodGet,
				http.MethodPut,
				http.MethodHead,
				http.MethodPost,
				http.MethodDelete,
				http.MethodOptions,
				http.MethodPatch,
			},
			AllowedHeaders:   commonS3Headers,
			ExposedHeaders:   commonS3Headers,
			AllowCredentials: true,
		}).Handler(handler)
	}
}

// CriticalErrorHandler handles critical server failures caused by
// `panic(logger.ErrCritical)` as done by `logger.CriticalIf`.
//
// It should be always the first / highest HTTP handler.
type CriticalErrorHandler struct{ Handler http.Handler }

func (h CriticalErrorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := recover(); err == logger.ErrCritical { // handle
			cmd.WriteErrorResponse(r.Context(), w, cmd.GetAPIError(cmd.ErrInternalError), r.URL, false)
			return
		} else if err != nil {
			panic(err) // forward other panic calls
		}
	}()
	h.Handler.ServeHTTP(w, r)
}
