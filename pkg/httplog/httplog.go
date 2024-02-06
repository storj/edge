// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package httplog

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	xhttp "storj.io/minio/cmd/http"
)

// Known headers and query string values that should be redacted and not logged.
// References:
// https://docs.aws.amazon.com/general/latest/gr/signature-version-2.html
// https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
var (
	confidentialQueries = map[string]struct{}{
		"prefix":             {},
		xhttp.AmzAccessKeyID: {},
		xhttp.AmzSignatureV2: {},
		xhttp.AmzSignature:   {},
		xhttp.AmzCredential:  {},
	}

	confidentialHeaders = map[string]struct{}{
		xhttp.Authorization: {},
		"Cookie":            {},
		xhttp.AmzCopySource: {},
	}
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
	Query                                   url.Values
	InsecureDisableConfidentialSanitization bool
}

// MarshalLogObject implements the zapcore.ObjectMarshaler interface.
func (o RequestQueryLogObject) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	for k, v := range o.Query {
		enc.AddString(k, hideConfidentialQuery(k, v, o.InsecureDisableConfidentialSanitization))
	}
	return nil
}

// MarshalJSON implements json.Marshal.
func (o RequestQueryLogObject) MarshalJSON() ([]byte, error) {
	data := make(map[string]string)
	for k, v := range o.Query {
		data[k] = hideConfidentialQuery(k, v, o.InsecureDisableConfidentialSanitization)
	}
	return json.Marshal(data)
}

// HeadersLogObject encodes an http.Header into a zap logging object.
type HeadersLogObject struct {
	Headers                                 http.Header
	InsecureDisableConfidentialSanitization bool
}

// MarshalLogObject implements the zapcore.ObjectMarshaler interface.
func (o HeadersLogObject) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	for k, v := range o.Headers {
		enc.AddString(k, hideConfidentialHeader(k, v, o.InsecureDisableConfidentialSanitization))
	}
	return nil
}

// MarshalJSON implements json.Marshal.
func (o HeadersLogObject) MarshalJSON() ([]byte, error) {
	data := make(map[string]string)
	for k, v := range o.Headers {
		data[k] = hideConfidentialHeader(k, v, o.InsecureDisableConfidentialSanitization)
	}
	return json.Marshal(data)
}

func hideConfidentialQuery(k string, vals []string, disable bool) string {
	if _, ok := confidentialQueries[k]; ok && !disable {
		return "[...]"
	}
	return strings.Join(vals, ",")
}

func hideConfidentialHeader(k string, vals []string, disable bool) string {
	if _, ok := confidentialHeaders[k]; ok && !disable {
		return "[...]"
	}
	return strings.Join(vals, ",")
}
