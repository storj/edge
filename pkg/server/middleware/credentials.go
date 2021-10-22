// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"context"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/memory"
	"storj.io/gateway-mt/pkg/authclient"
	"storj.io/gateway-mt/pkg/trustedip"
)

type credentialsCV struct{}

// Credentials contains an AccessKey, SecretKey, AccessGrant, and IsPublic flag.
type Credentials struct {
	AccessKey string
	authclient.AuthServiceResponse
	Error error
}

const (
	iso8601Format = "20060102T150405Z"
	yyyymmdd      = "20060102"
)

var accessRegexp = regexp.MustCompile("/access/.*\"")

// AccessKey implements mux.Middlware and saves the accesskey to context.
func AccessKey(authClient *authclient.AuthClient, trustedIPs trustedip.List, log *zap.Logger) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			// extract the access key id from the HTTP headers
			accessKeyID, err := GetAccessKeyID(r)
			if err != nil || accessKeyID == "" {
				next.ServeHTTP(w, r)
				return
			}
			var creds Credentials
			authResponse, err := authClient.ResolveWithCache(ctx, accessKeyID, trustedip.GetClientIP(trustedIPs, r))
			if err != nil {
				logError(log, err)
				creds.Error = err
				next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, credentialsCV{}, &creds)))
				return
			}

			// return a new context that contains the access grant
			credentials := Credentials{AccessKey: accessKeyID, AuthServiceResponse: *authResponse, Error: err}
			next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, credentialsCV{}, &credentials)))
		})
	}
}

func logError(log *zap.Logger, err error) {
	// avoid logging access keys from errors, e.g.
	// "Get \"http://localhost:8000/v1/access/12345\": dial tcp ..."
	msg := accessRegexp.ReplaceAllString(err.Error(), "[...]\"")

	mon.Event("gmt_unmapped_error",
		monkit.NewSeriesTag("api", "SYSTEM"),
		monkit.NewSeriesTag("error", msg))

	log.Error("system", zap.String("error", msg))
}

// GetAccess returns the credentials.
func GetAccess(ctx context.Context) *Credentials {
	creds, ok := ctx.Value(credentialsCV{}).(*Credentials)
	if !ok {
		return nil
	}
	return creds
}

// GetAccessKeyID returns the access key ID from the request and a signature validator.
func GetAccessKeyID(r *http.Request) (string, error) {
	// Speculatively parse for V4 and then V2.
	v4, errV4 := ParseV4(r)
	if errV4 == nil {
		return v4.Credential.AccessKeyID, nil
	}

	v2, errV2 := ParseV2(r)
	if errV2 == nil {
		return v2.AccessKeyID, nil
	}

	// Try parsing V2 or V4 credentials from multipart form credentials.
	// This attempt is made after other types because it requires creating a potentially
	// memory intensive cache of the POST'ed body data.
	var errMPV4, errMPV2 error
	if r.Method == "POST" {
		// create a reset-able body so we don't drain the request body for later
		const bodyBufferSize = int64(5 * memory.MiB)
		bodyCache, err := NewBodyCache(r.Body, bodyBufferSize)
		if err != nil {
			return "", err
		}
		r.Body = bodyCache
		defer func() {
			_, seekErr := bodyCache.Seek(0, io.SeekStart)
			err = errs.Combine(err, seekErr)
		}()

		// now read the body
		reader, err := getMultipartReader(r)
		if err != nil {
			return "", err
		}
		// Read multipart data, limiting to 5 mibyte, as Minio doees
		form, err := reader.ReadForm(bodyBufferSize)
		if err != nil {
			return "", err
		}
		// Canonicalize the form values into http.Header.
		formValues := make(http.Header)
		for k, v := range form.Value {
			formValues[http.CanonicalHeaderKey(k)] = v
		}

		v4, errMPV4 := ParseV4FromFormValues(formValues)
		if errMPV4 == nil {
			return v4.Credential.AccessKeyID, nil
		}

		v2, errMPV2 := ParseV2FromFormValues(formValues)
		if errMPV2 == nil {
			return v2.AccessKeyID, nil
		}
	}

	return "", errs.Combine(errV4, errV2, errMPV4, errMPV2, errors.New("no access key ID"))
}

var v4CredentialRegex = regexp.MustCompile("^(?P<akid>[^/]+)/(?P<date>[^/]+)/(?P<region>[^/]+)/(?P<service>[^/]+)/aws4_request$")

// V4Credential represents S3 V4 protocol credentials.
type V4Credential struct {
	AccessKeyID string
	Date        time.Time
	Region      string
	Service     string
}

// ParseV4CredentialError is the default error class for V4 parsing credential errors.
var ParseV4CredentialError = errs.Class("credential")

// ParseV4Credential parses the credential into it's parts.
func ParseV4Credential(data string) (*V4Credential, error) {
	vals := v4CredentialRegex.FindStringSubmatch(data)
	if len(vals) != 5 {
		return nil, ParseV4CredentialError.New("malformed")
	}

	d, err := time.Parse(yyyymmdd, vals[2])
	if err != nil {
		return nil, ParseV4CredentialError.New("invalid date")
	}

	return &V4Credential{
		AccessKeyID: vals[1],
		Date:        d,
		Region:      vals[3],
		Service:     vals[4],
	}, nil
}

// V4 represents S3 V4 all security related data.
type V4 struct {
	Credential    *V4Credential
	SignedHeaders []string
	Signature     string

	ContentSHA256 string
	Date          time.Time

	FromHeader bool
}

// ParseV4Error is the default error class for V4 parsing errors.
var ParseV4Error = errs.Class("parse v4")

// ParseV4FromHeaderError is the default error class for V4 parsing header errors.
var ParseV4FromHeaderError = errs.Class("header")

// ParseV4FromQueryError is the default error class for V4 parsing query errors.
var ParseV4FromQueryError = errs.Class("query")

// ParseV4FromMPartError is the default error class for V4 parsing multipart form errors.
var ParseV4FromMPartError = errs.Class("V4 multipart form")

// ParseV2FromMPartError is the default error class for V2 parsing multipart form errors.
var ParseV2FromMPartError = errs.Class("V2 multipart form")

var (
	v4AuthorizationRegex      = regexp.MustCompile("^AWS4-HMAC-SHA256 (?P<kvs>.+)$")
	v4AuthorizationFieldRegex = regexp.MustCompile("^(?P<key>[^,=]+)[=](?P<val>[^,]+)[,]?[ ]*")
)

// ParseV4FromHeader parses a V4 signature from the request headers.
func ParseV4FromHeader(r *http.Request) (_ *V4, err error) {
	authorization := r.Header.Get("Authorization")
	if authorization == "" {
		return nil, ParseV4FromHeaderError.New("authorization empty")
	}

	vals := v4AuthorizationRegex.FindStringSubmatch(authorization)
	if len(vals) != 2 {
		return nil, ParseV4FromHeaderError.New("authorization missing fields: %+v", vals)
	}

	kvs := vals[1]

	v4 := &V4{
		ContentSHA256: r.Header.Get("X-Amz-Content-SHA256"),
		FromHeader:    true,
	}

	v4.Date, err = time.Parse(iso8601Format, r.Header.Get("X-Amz-Date"))
	if err != nil {
		return nil, ParseV4FromHeaderError.New("invalid X-Amz-Date")
	}

	for kvs != "" {
		fields := v4AuthorizationFieldRegex.FindStringSubmatch(kvs)
		if len(fields) != 3 {
			return nil, ParseV4FromHeaderError.New("authorization field malformed %q", kvs)
		}

		key := fields[1]
		val := fields[2]

		switch key {
		case "Credential":
			v4.Credential, err = ParseV4Credential(val)
			if err != nil {
				return nil, ParseV4FromHeaderError.New("credential field malformed")
			}
		case "Signature":
			v4.Signature = val
		case "SignedHeaders":
			v4.SignedHeaders = strings.Split(val, ";")
		}

		kvs = kvs[len(fields[0]):]
	}

	return v4, nil
}

// ParseV4FromFormValues parses a V4 signature from the multipart form parameters.
func ParseV4FromFormValues(formValues http.Header) (_ *V4, err error) {

	if _, ok := formValues["X-Amz-Signature"]; !ok {
		return nil, ParseV4FromMPartError.New("no X-Amz-Signature field")
	}
	if _, ok := formValues["X-Amz-Date"]; !ok {
		return nil, ParseV4FromMPartError.New("no X-Amz-Date field")
	}
	if _, ok := formValues["X-Amz-Credential"]; !ok {
		return nil, ParseV4FromMPartError.New("no X-Amz-Credential field")
	}

	v4 := &V4{}
	v4.Credential, err = ParseV4Credential(formValues["X-Amz-Credential"][0])
	if err != nil {
		return nil, ParseV4FromMPartError.New("error parsing X-Amz-Credential")
	}
	v4.Signature = formValues["X-Amz-Signature"][0]

	v4.Date, err = time.Parse(iso8601Format, formValues["X-Amz-Date"][0])
	if err != nil {
		return nil, ParseV4FromMPartError.New("invalid X-Amz-Date")
	}
	return v4, nil
}

// ParseV2FromFormValues parses a V2 signature from the multipart form parameters.
func ParseV2FromFormValues(formValues http.Header) (_ *V2, err error) {
	var ok bool
	var AccessKeyID, Signature []string
	if AccessKeyID, ok = formValues[http.CanonicalHeaderKey("AWSAccessKeyId")]; !ok {
		return nil, ParseV2FromMPartError.New("no AWSAccessKeyId field")
	}
	if Signature, ok = formValues["Signature"]; !ok {
		return nil, ParseV2FromMPartError.New("no Signature field")
	}

	return &V2{AccessKeyID: AccessKeyID[0], Signature: Signature[0]}, nil

}

func getMultipartReader(r *http.Request) (*multipart.Reader, error) {
	if r.MultipartForm != nil {
		return nil, ParseV4FromMPartError.New("http: multipart already processed")
	}
	v := r.Header.Get("Content-Type")
	if v == "" {
		return nil, ParseV4FromMPartError.New("not multipart")
	}
	d, params, err := mime.ParseMediaType(v)
	if err != nil || !(d == "multipart/form-data" || d == "multipart/mixed") {
		return nil, ParseV4FromMPartError.New("not multipart")
	}
	boundary, ok := params["boundary"]
	if !ok {
		return nil, ParseV4FromMPartError.New("Missing boundary")
	}
	return multipart.NewReader(r.Body, boundary), nil
}

// ParseV4FromQuery parses a V4 signature from the query parameters.
func ParseV4FromQuery(r *http.Request) (_ *V4, err error) {
	q := r.URL.Query()

	algorithm := q.Get("X-Amz-Algorithm")
	if algorithm != "AWS4-HMAC-SHA256" {
		return nil, ParseV4FromQueryError.New("invalid algorithm: %q", algorithm)
	}

	v4 := &V4{}

	v4.Credential, err = ParseV4Credential(q.Get("X-Amz-Credential"))
	if err != nil {
		return nil, ParseV4FromQueryError.Wrap(err)
	}

	v4.SignedHeaders = strings.Split(q.Get("X-Amz-SignedHeaders"), ";")

	v4.Signature = r.URL.Query().Get("X-Amz-Signature")

	v4.ContentSHA256 = r.URL.Query().Get("X-Amz-Content-SHA256")
	if v4.ContentSHA256 == "" {
		v4.ContentSHA256 = "UNSIGNED-PAYLOAD"
	}

	v4.Date, err = time.Parse(iso8601Format, r.URL.Query().Get("X-Amz-Date"))
	if err != nil {
		return nil, ParseV4FromHeaderError.New("invalid X-Amz-Date")
	}

	return v4, nil
}

// ParseV4 parses a V4 signature from the request.
func ParseV4(r *http.Request) (*V4, error) {
	// Speculatively parse from the headers and then query parameters.
	v4, err1 := ParseV4FromHeader(r)
	if err1 == nil {
		return v4, nil
	}

	v4, err2 := ParseV4FromQuery(r)
	if err2 == nil {
		return v4, nil
	}

	return nil, ParseV4Error.Wrap(errs.Combine(err1, err2))
}

// V2 represents S3 V2 all security related data.
type V2 struct {
	AccessKeyID string
	Signature   string
	Expires     time.Time

	FromHeader bool
}

// ParseV2Error is the default error class for V2 parsing errors.
var ParseV2Error = errs.Class("parse v2")

// ParseV2FromHeaderError is the default error class for V2 parsing header errors.
var ParseV2FromHeaderError = errs.Class("header")

// ParseV2FromQueryError is the default error class for V2 parsing query errors.
var ParseV2FromQueryError = errs.Class("query")

var v2AuthorizationRegex = regexp.MustCompile("^AWS (?P<key>[^:]+):(?P<sig>.+)$")

// ParseV2FromHeader parses a V2 signature from the request headers.
func ParseV2FromHeader(r *http.Request) (_ *V2, err error) {
	authorization := r.Header.Get("Authorization")
	if authorization == "" {
		return nil, ParseV2FromHeaderError.New("authorization empty")
	}

	vals := v2AuthorizationRegex.FindStringSubmatch(authorization)
	if len(vals) != 3 {
		return nil, ParseV2FromHeaderError.New("malformed authorization")
	}

	v2 := &V2{
		AccessKeyID: vals[1],
		Signature:   vals[2],

		FromHeader: true,
	}

	return v2, nil
}

// ParseV2FromQuery parses a V2 signature from the query parameters.
func ParseV2FromQuery(r *http.Request) (_ *V2, err error) {
	// https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html#RESTAuthenticationQueryStringAuth
	v2 := &V2{
		AccessKeyID: r.URL.Query().Get("AWSAccessKeyId"),
		Signature:   r.URL.Query().Get("Signature"),
	}

	if v2.AccessKeyID == "" {
		return nil, ParseV2FromQueryError.New("no AWSAccessKeyId field")
	}
	if v2.Signature == "" {
		return nil, ParseV2FromQueryError.New("no Signature field")
	}

	return v2, nil
}

// ParseV2 parses a V2 signature from the request.
func ParseV2(r *http.Request) (*V2, error) {
	// Speculatively parse from the headers and then query parameters.
	v2, err1 := ParseV2FromHeader(r)
	if err1 == nil {
		return v2, nil
	}

	v2, err2 := ParseV2FromQuery(r)
	if err2 == nil {
		return v2, nil
	}

	return nil, ParseV2Error.Wrap(errs.Combine(err1, err2))
}
