// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/zeebo/errs"

	"storj.io/uplink"
)

type contextValue string

const (
	iso8601Format              = "20060102T150405Z"
	yyyymmdd                   = "20060102"
	accessGrant   contextValue = "AccessGrant"
)

// Signature middleware handles authorization without Minio.
type Signature struct {
	AuthClient func() (*AuthClient, error)
	TrustedIPs TrustedIPsList
}

// Middleware implements mux.Middlware.
func (s *Signature) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		// extract the access key id from the HTTP headers
		accessKeyID, validator, err := GetAccessKeyIDWithValidator(r)
		if err != nil {
			WriteError(ctx, w, err, r.URL)
			return
		}
		// lookup access grant and secret key from the auth service
		authClient, err := s.AuthClient()
		if err != nil {
			WriteError(ctx, w, err, r.URL)
			return
		}

		authResponse, err := authClient.GetAccess(ctx, accessKeyID, GetClientIP(s.TrustedIPs, r))
		if err != nil {
			WriteError(ctx, w, err, r.URL)
			return
		}
		// validate request using the secret key
		err = validator.IsRequestValid(r, authResponse.SecretKey)
		if err != nil {
			WriteError(ctx, w, err, r.URL)
			return
		}
		// if we reach here, the request is validated.  parse the access grant.
		accessGrant, err := uplink.ParseAccess(authResponse.AccessGrant)
		if err != nil {
			WriteError(ctx, w, err, r.URL)
			return
		}
		// return a new context that contains the access grant
		next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, accessGrant, accessGrant)))
	})
}

// GetAcessGrant returns the credentials.
func GetAcessGrant(ctx context.Context) *uplink.Access {
	return ctx.Value(accessGrant).(*uplink.Access)
}

// GetAccessKeyIDWithValidator returns the access key ID from the request and a signature validator.
func GetAccessKeyIDWithValidator(r *http.Request) (string, Validator, error) {
	// Speculatively parse for V4 and then V2.
	v4, err1 := ParseV4(r)
	if err1 == nil {
		return v4.Credential.AccessKeyID, v4, nil
	}

	v2, err2 := ParseV2(r)
	if err2 == nil {
		return v2.AccessKeyID, v2, nil
	}

	return "", nil, errs.Combine(err1, err2, errors.New("no access key ID"))
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

// Validator wraps basic IsRequestValid method.
//
// IsRequestValid validates the request's signature using secretKey and returns any error encountered.
// Implementations should use a constant-time comparison for security reasons.
type Validator interface {
	IsRequestValid(r *http.Request, secretKey string) (err error)
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

// valid returns true if the signature has all necessary fields.
func (v4 *V4) valid() bool {
	if v4.Credential == nil {
		return false
	}

	if v4.SignedHeaders == nil {
		return false
	}

	if v4.Signature == "" {
		return false
	}

	if v4.ContentSHA256 == "" {
		return false
	}

	if v4.Date.IsZero() {
		return false
	}

	return true
}

// IsRequestValid validates the v4 signature against a given request.
func (v4 *V4) IsRequestValid(r *http.Request, secretKey string) (err error) {
	ctx := r.Context()

	// Clone the original request and reset the clone headers to just the
	// ones that are signed. We will use the cloned request with the
	// standard AWS Go library to regenerate the signature.
	clone := r.Clone(ctx)
	clone.Header = http.Header{}
	for _, header := range v4.SignedHeaders {
		clone.Header.Set(header, r.Header.Get(header))
	}

	// Read the request payload to compute the checksum and reset the
	// original request and clone bodies. This will allow later readers of
	// the request to read the body.
	payload, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}

	r.Body = ioutil.NopCloser(bytes.NewReader(payload))
	clone.Body = ioutil.NopCloser(bytes.NewReader(payload))

	sum := sha256.Sum256(payload)
	payloadHash := hex.EncodeToString(sum[:])

	// Use either the header or query parameter signing depending on how
	// the original request's signature was detected.
	if v4.FromHeader {
		err = awsv4.NewSigner().SignHTTP(
			ctx,
			aws.Credentials{
				AccessKeyID:     v4.Credential.AccessKeyID,
				SecretAccessKey: secretKey,
				Expires:         v4.Credential.Date,
			},
			clone,
			payloadHash,
			v4.Credential.Service,
			v4.Credential.Region,
			v4.Date,
		)
		if err != nil {
			return err
		}
	} else {
		signedURI, signedHeaders, err := awsv4.NewSigner().PresignHTTP(
			ctx,
			aws.Credentials{
				AccessKeyID:     v4.Credential.AccessKeyID,
				SecretAccessKey: secretKey,
				Expires:         v4.Credential.Date,
			},
			clone,
			payloadHash,
			v4.Credential.Service,
			v4.Credential.Region,
			v4.Date,
		)
		if err != nil {
			return err
		}

		// TODO: Figure out what validation should be done for the
		//       signed URI and signed headers.
		fmt.Printf("Signed: %q %+v\n", signedURI, signedHeaders)
	}

	cv4, err := ParseV4(clone)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare([]byte(v4.Signature), []byte(cv4.Signature)) != 1 {
		return errors.New("Signature Mismatch")
	}

	return nil
}

// ParseV4Error is the default error class for V4 parsing errors.
var ParseV4Error = errs.Class("parse v4")

// ParseV4FromHeaderError is the default error class for V4 parsing header errors.
var ParseV4FromHeaderError = errs.Class("header")

// ParseV4FromQueryError is the default error class for V4 parsing query errors.
var ParseV4FromQueryError = errs.Class("query")

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

	if !v4.valid() {
		return nil, ParseV4FromHeaderError.New("missing required fields")
	}

	return v4, nil
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

	if !v4.valid() {
		return nil, ParseV4FromQueryError.New("missing required fields")
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

// valid returns true if the signature has all necessary fields.
func (v2 *V2) valid() bool {
	if v2.AccessKeyID == "" {
		return false
	}

	if v2.Signature == "" {
		return false
	}

	if v2.Expires.IsZero() {
		return false
	}

	return true
}

// IsRequestValid validates the v2 signature against a given request.
func (v2 *V2) IsRequestValid(r *http.Request, secretKey string) (err error) {
	// TODO: See if we can't do the same thing we did with v4 and reuse the
	// official AWS signer. The difficulty is that AWS's Go SDKs don't
	// expose a v2 signer. However, there is one in
	// aws-sdk-go/private/signer/v2/v2.go that could be reshaped for our
	// use. Unforunately there also appears to be multiple ways to do v2
	// signing with varying levels of flexibility (e.g.
	// https://docs.aws.amazon.com/general/latest/gr/signature-version-2.html,
	// https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html#RESTAuthenticationQueryStringAuth).
	// Specifically, one allows for `Expires`, but the other doesn't. One
	// also allows for 2 different signature methods via SignatureMethod.
	// Which of these is correct or if both are and the union is the full
	// spec is not known. Minio itself seems to only implement the simple
	// version. Also the simple version is the one the AWS cli generates.
	return errors.New("Unimplemented")
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

	if !v2.valid() {
		return nil, ParseV2FromHeaderError.New("missing required fields")
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

	if !v2.valid() {
		return nil, ParseV2FromQueryError.New("missing required fields")
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
