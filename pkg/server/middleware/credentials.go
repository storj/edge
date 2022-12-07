// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"context"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/jtolio/eventkit"
	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"storj.io/common/memory"
	"storj.io/gateway-mt/pkg/authclient"
	"storj.io/gateway-mt/pkg/errdata"
	"storj.io/gateway-mt/pkg/trustedip"
	"storj.io/minio/cmd"
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

var (
	ekCredentials = ek.Subscope("Credentials")

	accessRegexp = regexp.MustCompile("/access/.*\"")

	errNoAccessKey              = errs.New("no access key id")
	errMalformedAuthorizationV2 = errs.New("malformed authorization")
	errCredentialMalformed      = errs.New("malformed")
	errMalformedCredentialDate  = errs.New("invalid date")
	errInvalidDate              = errs.New("invalid X-Amz-Date")
	errInvalidAlgorithm         = errs.New("invalid algorithm")
	errInvalidDateHeader        = errs.New("invalid X-Amz-Date header")

	errInvalidQuery         = errs.Class("invalid query")
	errMissingFields        = errs.Class("missing fields")
	errMalformedPOSTRequest = errs.Class("malformed POST data")
)

// AccessKey implements mux.Middlware and saves the accesskey to context.
func AccessKey(authClient *authclient.AuthClient, trustedIPs trustedip.List, log *zap.Logger) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			// extract the access key id from the request
			accessKeyID, err := GetAccessKeyID(r)
			if err != nil {
				if errs.Is(err, errNoAccessKey) {
					next.ServeHTTP(w, r)
					return
				}

				errCode := errToAPIErrCode(err)
				var apiError cmd.APIError
				if errCode == 0 { // if we didn't map to anything, fall back to a generic error.
					apiError = cmd.APIError{
						Code:           "InvalidCredentials",
						Description:    err.Error(),
						HTTPStatusCode: http.StatusBadRequest,
					}
				} else {
					apiError = cmd.GetAPIError(errCode)
				}
				cmd.WriteErrorResponse(ctx, w, apiError, r.URL, false)
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
			credentials := Credentials{AccessKey: accessKeyID, AuthServiceResponse: authResponse, Error: err}
			next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, credentialsCV{}, &credentials)))
		})
	}
}

func logError(log *zap.Logger, err error) {
	// avoid logging access keys from errors, e.g.
	// "Get \"http://localhost:20000/v1/access/12345\": dial tcp ..."
	msg := accessRegexp.ReplaceAllString(err.Error(), "[...]\"")
	var level zapcore.Level
	metricName := "gmt_authservice_error"

	switch errdata.GetStatus(err, http.StatusOK) {
	case http.StatusUnauthorized, http.StatusBadRequest:
		level = zap.DebugLevel
	case http.StatusInternalServerError:
		level = zap.ErrorLevel
	default:
		level = zap.ErrorLevel
		metricName = "gmt_unmapped_error"
	}

	ekCredentials.Event(metricName, eventkit.String("api", "SYSTEM"), eventkit.String("error", msg))

	ce := log.Check(level, "system")
	if ce != nil {
		ce.Write(zap.String("error", msg))
	}
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
	switch {
	case isRequestSignatureV4(r):
		v4, err := ParseV4FromHeader(r)
		if err != nil {
			return "", err
		}
		return v4.Credential.AccessKeyID, nil
	case isRequestPresignedSignatureV4(r):
		v4, err := ParseV4FromQuery(r)
		if err != nil {
			return "", err
		}
		return v4.Credential.AccessKeyID, nil
	case isRequestSignatureV2(r):
		v2, err := ParseV2FromHeader(r)
		if err != nil {
			return "", err
		}
		return v2.AccessKeyID, nil
	case isRequestPresignedSignatureV2(r):
		v2, err := ParseV2FromQuery(r)
		if err != nil {
			return "", err
		}
		return v2.AccessKeyID, nil
	case isRequestPostPolicySignature(r):
		key, err := ParseFromForm(r)
		if err != nil {
			return "", err
		}
		return key, nil
	default:
		return "", errNoAccessKey
	}
}

func isRequestSignatureV4(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256")
}

func isRequestSignatureV2(r *http.Request) bool {
	return !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") &&
		strings.HasPrefix(r.Header.Get("Authorization"), "AWS")
}

func isRequestPresignedSignatureV4(r *http.Request) bool {
	_, ok := r.URL.Query()["X-Amz-Credential"]
	return ok
}

func isRequestPresignedSignatureV2(r *http.Request) bool {
	_, ok := r.URL.Query()["AWSAccessKeyId"]
	return ok
}

func isRequestPostPolicySignature(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Content-Type"), "multipart/form-data") &&
		r.Method == http.MethodPost
}

var v4CredentialRegex = regexp.MustCompile("^(?P<akid>[^/]+)/(?P<date>[^/]+)/(?P<region>[^/]+)?/(?P<service>[^/]+)/aws4_request$")

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
		return nil, ParseV4CredentialError.Wrap(errCredentialMalformed)
	}

	d, err := time.Parse(yyyymmdd, vals[2])
	if err != nil {
		return nil, ParseV4CredentialError.Wrap(errMalformedCredentialDate)
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
	vals := v4AuthorizationRegex.FindStringSubmatch(r.Header.Get("Authorization"))
	if len(vals) != 2 {
		return nil, ParseV4FromHeaderError.Wrap(errMissingFields.New("%+v", vals))
	}

	kvs := vals[1]

	v4 := &V4{
		ContentSHA256: r.Header.Get("X-Amz-Content-SHA256"),
		FromHeader:    true,
	}

	v4.Date, err = time.Parse(iso8601Format, r.Header.Get("X-Amz-Date"))
	if err != nil {
		return nil, ParseV4FromHeaderError.Wrap(errInvalidDateHeader)
	}

	for kvs != "" {
		fields := v4AuthorizationFieldRegex.FindStringSubmatch(kvs)
		if len(fields) != 3 {
			return nil, ParseV4FromHeaderError.Wrap(errMissingFields.New("expected exactly three components: Credential, SignedHeaders, and Signature"))
		}

		key := fields[1]
		val := fields[2]

		switch key {
		case "Credential":
			v4.Credential, err = ParseV4Credential(val)
			if err != nil {
				return nil, ParseV4FromHeaderError.Wrap(err)
			}
		case "Signature":
			v4.Signature = val
		case "SignedHeaders":
			v4.SignedHeaders = strings.Split(val, ";")
		}

		kvs = kvs[len(fields[0]):]
	}

	mon.Counter("auth",
		monkit.NewSeriesTag("version", "4"),
		monkit.NewSeriesTag("type", "header")).Inc(1)

	return v4, nil
}

// ParseV4FromFormValues parses a V4 signature from the multipart form parameters.
func ParseV4FromFormValues(formValues http.Header) (_ *V4, err error) {
	if _, ok := formValues["X-Amz-Signature"]; !ok {
		return nil, ParseV4FromMPartError.Wrap(errMissingFields.New("no X-Amz-Signature field"))
	}
	if _, ok := formValues["X-Amz-Date"]; !ok {
		return nil, ParseV4FromMPartError.Wrap(errMissingFields.New("no X-Amz-Date field"))
	}
	if _, ok := formValues["X-Amz-Credential"]; !ok {
		return nil, ParseV4FromMPartError.Wrap(errMissingFields.New("no X-Amz-Credential field"))
	}

	v4 := &V4{}
	v4.Credential, err = ParseV4Credential(formValues["X-Amz-Credential"][0])
	if err != nil {
		return nil, ParseV4FromMPartError.Wrap(err)
	}
	v4.Signature = formValues["X-Amz-Signature"][0]

	v4.Date, err = time.Parse(iso8601Format, formValues["X-Amz-Date"][0])
	if err != nil {
		return nil, ParseV4FromMPartError.Wrap(errInvalidDate)
	}

	mon.Counter("auth",
		monkit.NewSeriesTag("version", "4"),
		monkit.NewSeriesTag("type", "multipart")).Inc(1)

	return v4, nil
}

// ParseV2FromFormValues parses a V2 signature from the multipart form parameters.
func ParseV2FromFormValues(formValues http.Header) (_ *V2, err error) {
	var ok bool
	var AccessKeyID, Signature []string
	if AccessKeyID, ok = formValues[http.CanonicalHeaderKey("AWSAccessKeyId")]; !ok {
		return nil, ParseV2FromMPartError.Wrap(errMissingFields.New("no AWSAccessKeyId field"))
	}
	if Signature, ok = formValues["Signature"]; !ok {
		return nil, ParseV2FromMPartError.Wrap(errMissingFields.New("no Signature field"))
	}

	mon.Counter("auth",
		monkit.NewSeriesTag("version", "2"),
		monkit.NewSeriesTag("type", "multipart")).Inc(1)

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
		return nil, ParseV4FromQueryError.Wrap(errInvalidAlgorithm)
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
		return nil, ParseV4FromQueryError.Wrap(errInvalidDate)
	}

	mon.Counter("auth",
		monkit.NewSeriesTag("version", "4"),
		monkit.NewSeriesTag("type", "query")).Inc(1)

	return v4, nil
}

// V2 represents S3 V2 all security related data.
type V2 struct {
	AccessKeyID string
	Signature   string
	Expires     time.Time

	FromHeader bool
}

// ParseV2FromHeaderError is the default error class for V2 parsing header errors.
var ParseV2FromHeaderError = errs.Class("header")

// ParseV2FromQueryError is the default error class for V2 parsing query errors.
var ParseV2FromQueryError = errs.Class("query")

var v2AuthorizationRegex = regexp.MustCompile("^AWS (?P<key>[^:]+):(?P<sig>.+)$")

// ParseV2FromHeader parses a V2 signature from the request headers.
func ParseV2FromHeader(r *http.Request) (_ *V2, err error) {
	vals := v2AuthorizationRegex.FindStringSubmatch(r.Header.Get("Authorization"))
	if len(vals) != 3 {
		return nil, ParseV2FromHeaderError.Wrap(errMalformedAuthorizationV2)
	}

	v2 := &V2{
		AccessKeyID: vals[1],
		Signature:   vals[2],

		FromHeader: true,
	}

	mon.Counter("auth",
		monkit.NewSeriesTag("version", "2"),
		monkit.NewSeriesTag("type", "header")).Inc(1)

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
		return nil, ParseV2FromQueryError.Wrap(errInvalidQuery.New("no AWSAccessKeyId field"))
	}
	if v2.Signature == "" {
		return nil, ParseV2FromQueryError.Wrap(errInvalidQuery.New("no Signature field"))
	}

	mon.Counter("auth",
		monkit.NewSeriesTag("version", "2"),
		monkit.NewSeriesTag("type", "query")).Inc(1)

	return v2, nil
}

// ParseFromForm parses V2 or V4 credentials from multipart form credentials.
func ParseFromForm(r *http.Request) (string, error) {
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
		return "", errMalformedPOSTRequest.Wrap(err)
	}
	// Read multipart data, limiting to 5 mibyte, as Minio doees
	form, err := reader.ReadForm(bodyBufferSize)
	if err != nil {
		return "", errMalformedPOSTRequest.Wrap(err)
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

	return "", errs.Combine(errMPV4, errMPV2)
}

func errToAPIErrCode(err error) cmd.APIErrorCode {
	switch {
	case errs.Is(err, errMalformedAuthorizationV2):
		return cmd.ErrMissingFieldsV2
	case errs.Is(err, errCredentialMalformed):
		return cmd.ErrCredMalformed
	case errs.Is(err, errMalformedCredentialDate):
		return cmd.ErrMalformedCredentialDate
	case errs.Is(err, errInvalidDate):
		return cmd.ErrMalformedPresignedDate
	case errs.Is(err, errInvalidAlgorithm):
		return cmd.ErrInvalidQuerySignatureAlgo
	case errs.Is(err, errInvalidDateHeader):
		return cmd.ErrMissingDateHeader
	case errInvalidQuery.Has(err):
		return cmd.ErrInvalidQueryParams
	case errMissingFields.Has(err):
		return cmd.ErrMissingFields
	case errMalformedPOSTRequest.Has(err):
		return cmd.ErrMalformedPOSTRequest
	default:
		return 0
	}
}
