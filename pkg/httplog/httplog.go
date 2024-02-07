// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package httplog

import (
	"net/http"
	"net/url"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	xhttp "storj.io/minio/cmd/http"
)

// StatusLevel takes an HTTP status and returns an appropriate log level.
func StatusLevel(status int) zapcore.Level {
	switch {
	case status == 501:
		return zap.WarnLevel
	case status >= 500:
		return zap.ErrorLevel
	default:
		return zap.DebugLevel
	}
}

// RequestQueryLogObject encodes a URL query string into a zap logging object.
type RequestQueryLogObject struct {
	Query  url.Values
	LogAll bool
}

// MarshalLogObject implements the zapcore.ObjectMarshaler interface.
func (o *RequestQueryLogObject) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	for k, v := range o.Query {
		if o.LogAll {
			enc.AddString(k, strings.Join(v, ","))
			continue
		}

		var val string
		// obfuscate any credentials or confidential information in the query value.
		// https://docs.aws.amazon.com/general/latest/gr/signature-version-2.html
		// https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
		switch k {
		case "prefix", xhttp.AmzAccessKeyID, xhttp.AmzSignatureV2, xhttp.AmzSignature, xhttp.AmzCredential:
			val = "[...]"
		default:
			val = strings.Join(v, ",")
		}
		enc.AddString(k, val)
	}
	return nil
}

// HeadersLogObject encodes an http.Header into a zap logging object.
type HeadersLogObject struct {
	Headers http.Header
	LogAll  bool
}

// MarshalLogObject implements the zapcore.ObjectMarshaler interface.
func (o *HeadersLogObject) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	for k, v := range o.Headers {
		if o.LogAll {
			enc.AddString(k, strings.Join(v, ","))
			continue
		}

		var val string
		// obfuscate any credentials and sensitive information in headers.
		switch k {
		case xhttp.Authorization, "Cookie", xhttp.AmzCopySource:
			val = "[...]"
		default:
			val = strings.Join(v, ",")
		}
		enc.AddString(k, val)
	}
	return nil
}
