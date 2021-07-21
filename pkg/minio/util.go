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
	"net/http"
	"reflect"
	"unsafe"
	_ "unsafe" // for go:linkname

	"github.com/minio/minio/cmd"
	"github.com/minio/minio/cmd/logger"
)

// TODO: Revisit this when we update Minio.
// https://github.com/storj/minio/commit/04e6dc87c349a1c51f80fbe3f60eb1716ab349e9

// SetGlobalCLI offers an alternative to handleCommonCmdArgs to set global CLI context options.
// This is needed by Storj to (at least) ensure that ETags are not random.
func SetGlobalCLI(json, quiet, anonymous bool, addr string, strictS3Compat bool) {
	GlobalCLIContext.JSON = json
	GlobalCLIContext.Quiet = quiet
	GlobalCLIContext.Anonymous = anonymous
	GlobalCLIContext.Addr = addr
	GlobalCLIContext.StrictS3Compat = strictS3Compat
}

// InitCustomStore initializes an IAM store, shortcutting much of minio's startup.
func InitCustomStore(store cmd.IAMStorageAPI, sysType cmd.UsersSysType) {
	iamSys := cmd.NewIAMSys()
	rs := reflect.ValueOf(iamSys).Elem()
	setUnexportedField(rs.Field(8), store)
	setUnexportedField(rs.Field(1), sysType)
	GlobalIAMSys = iamSys
}

func setUnexportedField(field reflect.Value, value interface{}) {
	reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Set(reflect.ValueOf(value))
}

// ProjectUsageLimit storage Satellite project usage limit.
type ProjectUsageLimit cmd.GenericError

func (e ProjectUsageLimit) Error() string {
	return "You have reached your Storj project upload limit on the Satellite."
}

// CriticalErrorHandler handles critical server failures caused by
// `panic(logger.ErrCritical)` as done by `logger.CriticalIf`.
//
// It should be always the first / highest HTTP handler.
type CriticalErrorHandler struct{ Handler http.Handler }

func (h CriticalErrorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := recover(); err == logger.ErrCritical { // handle
			WriteErrorResponse(r.Context(), w, GetAPIError(cmd.ErrInternalError), r.URL)
			return
		} else if err != nil {
			panic(err) // forward other panic calls
		}
	}()
	h.Handler.ServeHTTP(w, r)
}
