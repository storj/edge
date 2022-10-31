// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

// Package signed provides verification of requests signed with AWS Signature
// Version 4 machinery. Signed requests enable the usage of non-public access
// grants while requesting an object.
//
// The parsing part of the package (parseSigningInfo and child types/functions)
// used MinIO's parsing code [0] as an edge-case reference.
//
// The verification/re-signing part of the package (VerifySigningInfo and child
// types/functions) strictly follows Signature Version 4 signing process [1].
//
// Some parts of the signing process are tuned specifically for linksharing. For
// example, we always assume an empty request body as we only allow HEAD and GET
// requests.
//
// [0]:
//   - https://github.com/minio/minio/blob/e0d3a8c1f4e52bb4a7d82f7f369b6796103740b3/cmd/signature-v4-parser.go
//
// [1]:
//   - https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
//   - https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html
package signed

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zeebo/errs"
)

const (
	iso8601TimeLayout   = "20060102T150405Z"
	yyyymmddTimeLayout  = "20060102"
	v4SigningAlgorithm  = "AWS4-HMAC-SHA256"
	emptyBodySHA256Hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// ErrMissingAuthorizationHeader indicates that the Authorization header for a
// particular request was not found. It's used to differentiate between signed
// requests that have invalid signing info and unsigned requests trying to use
// non-public access grant.
var ErrMissingAuthorizationHeader = errs.New("missing Authorization header")

// VerifySigningInfo reports whether r's signature is valid and constructed with
// secretAccessKey. The function additionally performs signature time validity
// check using currentTime as the current time. Signature time skewed backward
// or onwards up to validityTolerance will be tolerated.
//
// TODO(artur): add fuzz test for VerifySigningInfo vide
// https://pkg.go.dev/testing@master#hdr-Fuzzing.
func VerifySigningInfo(r *http.Request, secretAccessKey string, currentTime time.Time, validityTolerance time.Duration) error {
	errVerification := errs.Class("signing info verification")

	if r == nil {
		return errVerification.Wrap(ErrMissingAuthorizationHeader)
	}

	authorizationValue := r.Header.Get("Authorization")
	if authorizationValue == "" {
		return errVerification.Wrap(ErrMissingAuthorizationHeader)
	}

	info, err := parseSigningInfo(authorizationValue)
	if err != nil {
		return errVerification.Wrap(err)
	}

	headers, err := extractHeaders(info.signedHeaders, r)
	if err != nil {
		return errVerification.Wrap(err)
	}

	date := r.Header.Get("X-Amz-Date")
	if date == "" {
		date = r.Header.Get("Date")
	}

	t, err := time.Parse(iso8601TimeLayout, date)
	if err != nil {
		return errVerification.Wrap(err)
	}

	// Step 1: https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
	canonicalRequest := canonicalizeRequest(r, headers)

	// Step 2: https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
	stringToSign := createStringToSign(canonicalRequest, info.credential.buildScope(), t)

	// Step 3: https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
	reg, svc, req := info.credential.scope.region, info.credential.scope.service, info.credential.scope.request

	signature := calculateSignature(secretAccessKey, reg, svc, req, stringToSign, t)

	// Step 4: comparison!
	if subtle.ConstantTimeCompare([]byte(info.signature), []byte(signature)) != 1 {
		return errVerification.New("signature mismatch")
	}

	if currentTime.Add(-validityTolerance).After(t) || currentTime.Add(validityTolerance).Before(t) {
		return errVerification.New("signature time too skewed")
	}

	return nil
}

// extractHeaders extracts signedHeaders from r.
//
// TODO(artur): better doc.
func extractHeaders(signedHeaders []string, r *http.Request) (http.Header, error) {
	extracted := make(http.Header)

	for _, header := range signedHeaders {
		if v, ok := r.Header[http.CanonicalHeaderKey(header)]; ok {
			extracted[http.CanonicalHeaderKey(header)] = v
			continue
		}
		// If we don't find the signed header in headers, we fall back to
		// request attributes.
		//
		// Go HTTP server strips off Expect, Host and Transfer-Encoding.
		//
		// Content-Length is normally excluded from the signature calculation,
		// but some clients still use it, so we try to be most compatible here.
		switch header {
		case "content-length":
			extracted.Set(header, strconv.FormatInt(r.ContentLength, 10))
		case "expect":
			extracted.Set(header, "100-continue")
		case "host":
			extracted.Set(header, r.Host)
		case "transfer-encoding":
			extracted[http.CanonicalHeaderKey(header)] = r.TransferEncoding
		default:
			return nil, errs.New("signed header %q not found", header)
		}
	}

	return extracted, nil
}

// canonicalizeRequest creates a canonical string from r and headers (signed).
//
// V4's spec instructs us to double-escape the request's URI for all AWS
// services except S3. For S3, we only need to perform escaping once.
// Linksharing is an S3-like service as its URL contains bucket, prefix, and
// object path. We escape using (*URL).EscapedPath method, but it's not fully
// Amazon-style compatible (for example, it does not change +'s to %2B's). We
// don't do the Amazon-style escaping because AWS SDK for Go
// (https://github.com/aws/aws-sdk-go) also does not follow the spec in this
// regard, and we test against the signatures it produces.
//
// TODO(artur): send a patch to AWS SDK for Go rewriting their escaping logic to
// follow the V4's spec thoroughly. AWS SDK for Go Version 2
// (https://github.com/aws/aws-sdk-go-v2) suffers from the same problem (the
// signing code seems to be a copy-paste of Version 1's). When fixed, it will be
// great to have it fixed here, but it's not a show-stopper given that both SDKs
// never received many complaints about this behavior (I only found one issue
// that might be related: https://github.com/aws/aws-sdk-go/issues/3592).
//
// It assumes an empty request body as we only allow HEAD and GET requests given
// the service's nature.
func canonicalizeRequest(r *http.Request, headers http.Header) string {
	return strings.Join([]string{
		r.Method,
		r.URL.EscapedPath(),
		strings.ReplaceAll(r.URL.Query().Encode(), "+", "%20"),
		canonicalizeHeaders(headers),
		createSignedHeaders(headers),
		emptyBodySHA256Hash,
	}, "\n")
}

func canonicalizeHeaders(headers http.Header) string {
	var keys []string
	keysValues := make(http.Header)

	for k, v := range headers {
		l := strings.ToLower(k)
		keys = append(keys, l)
		keysValues[l] = v
	}

	sort.Strings(keys)

	var b strings.Builder

	for _, k := range keys {
		b.WriteString(k)
		b.WriteRune(':')
		for i, v := range keysValues[k] {
			if i > 0 {
				b.WriteRune(',')
			}
			b.WriteString(trimAll(v))
		}
		b.WriteRune('\n')
	}

	return b.String()
}

func trimAll(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func createSignedHeaders(headers http.Header) string {
	var ret []string

	for k := range headers {
		ret = append(ret, strings.ToLower(k))
	}

	sort.Strings(ret)

	return strings.Join(ret, ";")
}

func createStringToSign(canonicalRequest, scope string, t time.Time) string {
	canonicalRequestSHA256Sum := sha256.Sum256([]byte(canonicalRequest))

	return strings.Join([]string{
		v4SigningAlgorithm,
		t.Format(iso8601TimeLayout),
		scope,
		hex.EncodeToString(canonicalRequestSHA256Sum[:]),
	}, "\n")
}

func calculateSignature(secretAccessKey, region, service, request, stringToSign string, t time.Time) string {
	keySigning := deriveSigningKey(secretAccessKey, region, service, request, t)
	return hex.EncodeToString(hmacSHA256(keySigning, []byte(stringToSign)))
}

func deriveSigningKey(keySecret, region, service, request string, t time.Time) []byte {
	keyDate := hmacSHA256([]byte("AWS4"+keySecret), []byte(t.Format(yyyymmddTimeLayout)))
	keyRegion := hmacSHA256(keyDate, []byte(region))
	keyService := hmacSHA256(keyRegion, []byte(service))
	return hmacSHA256(keyService, []byte(request))
}

func hmacSHA256(key []byte, data []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(data)
	return hash.Sum(nil)
}

// signingInfo represents a structured form of AWS Signature Version 4's
// Authorization header value.
type signingInfo struct {
	credential    parsedCredential
	signedHeaders []string
	signature     string
}

// parseSigningInfo parses the Authorization header value of the form below into
// signingInfo.
//
// AWS4-HMAC-SHA256 Credential=accessKeyID/scope, SignedHeaders=..., Signature=...
func parseSigningInfo(authorizationValue string) (signingInfo, error) {
	errSigningInfo := errs.Class("signing info")

	// We don't care about Access Key ID in the Authorization header value as we
	// get it from the URL. With this context in mind, we can remove all spaces.
	//
	// TODO(artur): should we verify Access Key ID? It seems a little excessive.
	authorizationValue = strings.ReplaceAll(authorizationValue, " ", "")

	if !strings.HasPrefix(authorizationValue, v4SigningAlgorithm) {
		return signingInfo{}, errSigningInfo.New("invalid algorithm")
	}

	// Strip off the algorithm prefix after we made sure we support it.
	authorizationValue = authorizationValue[len(v4SigningAlgorithm):]

	parts := strings.SplitN(authorizationValue, ",", 3)
	if len(parts) < 3 {
		return signingInfo{}, errSigningInfo.New("invalid number of parts")
	}

	credential, err := parseCredential(parts[0])
	if err != nil {
		return signingInfo{}, errSigningInfo.Wrap(err)
	}

	signedHeaders, err := parseSignedHeaders(parts[1])
	if err != nil {
		return signingInfo{}, errSigningInfo.Wrap(err)
	}

	signature, err := parseSignature(parts[2])
	if err != nil {
		return signingInfo{}, errSigningInfo.Wrap(err)
	}

	return signingInfo{
		credential:    credential,
		signedHeaders: signedHeaders,
		signature:     signature,
	}, nil
}

// parsedCredential represents a structured form of the Credential part from the
// Authorization header value.
type parsedCredential struct {
	accessKeyID string
	scope       struct {
		date    time.Time
		region  string
		service string
		request string
	}
}

func (p parsedCredential) buildScope() string {
	return strings.Join([]string{
		p.scope.date.Format(yyyymmddTimeLayout),
		p.scope.region,
		p.scope.service,
		p.scope.request,
	}, "/")
}

// parseCredential parses Credential part into its structured form.
func parseCredential(credential string) (ret parsedCredential, err error) {
	errCredential := errs.Class("Credential")

	fields := strings.SplitN(credential, "=", 2)
	if len(fields) < 2 {
		return parsedCredential{}, errCredential.New("invalid number of fields")
	}

	if fields[0] != "Credential" {
		return parsedCredential{}, errCredential.New("not a Credential")
	}

	// Our Access Key IDs never contain forward slashes, so we can treat forward
	// slashes as final separators.
	elements := strings.SplitN(fields[1], "/", 5)
	if len(elements) < 5 {
		return parsedCredential{}, errCredential.New("invalid number of elements")
	}

	ret.accessKeyID = elements[0]

	ret.scope.date, err = time.Parse(yyyymmddTimeLayout, elements[1])
	if err != nil {
		return parsedCredential{}, errCredential.New("invalid date: %w", err)
	}

	ret.scope.region = elements[2]

	if elements[3] != "linksharing" {
		return parsedCredential{}, errCredential.New("invalid service")
	}
	if elements[4] != "aws4_request" {
		return parsedCredential{}, errCredential.New("invalid request")
	}

	ret.scope.service = elements[3]
	ret.scope.request = elements[4]

	return ret, nil
}

// parseSignedHeaders parses SignedHeaders part into a slice of headers.
func parseSignedHeaders(signedHeaders string) ([]string, error) {
	errSignedHeaders := errs.Class("SignedHeaders")

	fields := strings.SplitN(signedHeaders, "=", 2)
	if len(fields) < 2 {
		return nil, errSignedHeaders.New("invalid number of fields")
	}

	if fields[0] != "SignedHeaders" {
		return nil, errSignedHeaders.New("not a SignedHeaders")
	}
	if fields[1] == "" {
		return nil, errSignedHeaders.New("empty")
	}

	headers := strings.Split(fields[1], ";")

	// The list of signed headers must contain the "host" header.
	for _, h := range headers {
		if h == "host" {
			return headers, nil
		}
	}

	return nil, errSignedHeaders.New("host header is mandatory")
}

// parseSignature parses Signature part.
func parseSignature(signature string) (string, error) {
	errSignature := errs.Class("Signature")

	fields := strings.SplitN(signature, "=", 2)
	if len(fields) < 2 {
		return "", errSignature.New("invalid number of fields")
	}

	if fields[0] != "Signature" {
		return "", errSignature.New("not a Signature")
	}
	if fields[1] == "" {
		return "", errSignature.New("empty")
	}

	return fields[1], nil
}
