// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package signed

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrMissingAuthorizationHeader(t *testing.T) {
	err := VerifySigningInfo(nil, "", time.Time{}, 0)

	assert.ErrorIs(t, err, ErrMissingAuthorizationHeader)

	r, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, "https://link.storjshare.io/raw/AKIAIOSFODNN7EXAMPLE/b/o", nil)
	require.NoError(t, err)

	err = VerifySigningInfo(r, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", time.Now(), 15*time.Minute)

	assert.ErrorIs(t, err, ErrMissingAuthorizationHeader)
}

func TestVerifySigningInfo(t *testing.T) {
	// The following code was used to generate valid signatures for test cases
	// below (SDK version: v1.42.25):
	//
	// import (
	// 	"net/http"
	// 	"time"
	//
	// 	"github.com/aws/aws-sdk-go/aws/credentials"
	// 	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	// )
	//
	// ...
	//
	// c := credentials.NewCredentials(&credentials.StaticProvider{
	// 	Value: credentials.Value{
	// 		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
	// 		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	// 	}})
	//
	// signer := v4.NewSigner(c, func(s *v4.Signer) {
	// 	s.DisableURIPathEscaping = true
	// })
	//
	// r, err := http.NewRequest(http.MethodGet, "https://link.eu1.storjshare.io/raw/AKIAIOSFODNN7EXAMPLE/b/o", nil)
	// if err != nil {
	// 	panic(err)
	// }
	//
	// if _, err = signer.Sign(r, nil, "linksharing", "eu1", time.Unix(1640867116, 0)); err != nil {
	// 	panic(err)
	// }
	for i, tt := range [...]struct {
		headers map[string]string
		wantErr bool
	}{
		{
			headers: nil,
			wantErr: true,
		},
		{
			headers: map[string]string{
				"Authorization": "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20211230/eu1/linksharing/aws4_request, SignedHeaders=host;x-amz-date, Signature=22aa9f54124d4f1bb89c9ba733513c83710a6826908adcc8a1b97577a4c543ec",
			},
			wantErr: true,
		},
		{
			headers: map[string]string{
				"Authorization": "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/19700101/eu1/linksharing/aws4_request, SignedHeaders=host;x-amz-date, Signature=0000000000000000000000000000000000000000000000000000000000000000",
				"X-Amz-Date":    "20211230T122516Z",
			},
			wantErr: true,
		},
		{
			headers: map[string]string{
				"Authorization": "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20211230/eu1/linksharing/aws4_request, SignedHeaders=host;x-amz-date, Signature=47045f7ebb8fcfc2003957eb072eec28e8e433f6926c7ce1c1535dec9c2f09d9",
				"X-Amz-Date":    "20211230T121015Z", // 20211230T122516Z - 15m1s
			},
			wantErr: true,
		},
		{
			headers: map[string]string{
				"Authorization": "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20211230/eu1/linksharing/aws4_request, SignedHeaders=host;x-amz-date, Signature=fb8e27a8cd8693cea0ece617d0fc6aec44b08fcf45e89014a78edb259c12f895",
				"X-Amz-Date":    "20211230T124018Z", // 20211230T122516Z + 15m2s
			},
			wantErr: true,
		},
		{
			headers: map[string]string{
				"Authorization": "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20211230/eu1/linksharing/aws4_request, SignedHeaders=host;x-amz-date, Signature=22aa9f54124d4f1bb89c9ba733513c83710a6826908adcc8a1b97577a4c543ec",
				"X-Amz-Date":    "20211230T122516Z",
			},
			wantErr: false,
		},
		{
			headers: map[string]string{
				"Authorization": "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20211230/eu1/linksharing/aws4_request, SignedHeaders=host;x-amz-date, Signature=d6c784d6ff6978f456abec109bdb3150f674ac3db2441551e01135036ccd3883",
				"X-Amz-Date":    "20211230T121017Z", // 20211230T122516Z - 14m59s
			},
			wantErr: false,
		},
		{
			headers: map[string]string{
				"Authorization": "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20211230/eu1/linksharing/aws4_request, SignedHeaders=host;x-amz-date, Signature=ccdb4bd3fe0861c81ab4d31800c67d08456525dd72f4c10744ba5dbaeadd8507",
				"X-Amz-Date":    "20211230T124016Z", // 20211230T122516Z + 15m
			},
			wantErr: false,
		},
	} {
		r, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, "https://link.eu1.storjshare.io/raw/AKIAIOSFODNN7EXAMPLE/b/o", nil)
		require.NoError(t, err, i)

		for k, v := range tt.headers {
			r.Header.Set(k, v)
		}

		err = VerifySigningInfo(r, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", time.Unix(1640867116, 0), 15*time.Minute)

		assert.Equal(t, tt.wantErr, err != nil, i)
	}
}

func TestParseSigningInfo(t *testing.T) {
	for i, tt := range [...]struct {
		authorizationValue string
		want               signingInfo
		wantErr            bool
	}{
		{
			authorizationValue: "",
			want:               signingInfo{},
			wantErr:            true,
		},
		{
			authorizationValue: "AWS4-HMAC-SHA1",
			want:               signingInfo{},
			wantErr:            true,
		},
		{
			authorizationValue: "AWS4-HMAC-SHA256",
			want:               signingInfo{},
			wantErr:            true,
		},
		{
			authorizationValue: "AWS4-HMAC-SHA256 Credential=AKID/20211229/eu1/linksharing/aws4_request",
			want:               signingInfo{},
			wantErr:            true,
		},
		{
			authorizationValue: "AWS4-HMAC-SHA256 Credential=AKID/20211229/eu1/linksharing/aws4_request, SignedHeaders=host",
			want:               signingInfo{},
			wantErr:            true,
		},
		{
			authorizationValue: " AWS4-HMAC-SHA256  Credential   =    AKID/20211229/eu1/linksharing/aws4_request  ,   SignedHeaders = host,Signature=...      ",
			want: signingInfo{
				credential: parsedCredential{
					accessKeyID: "AKID",
					scope: struct {
						date                     time.Time
						region, service, request string
					}{
						date:    mustParseTime("20060102", "20211229"),
						region:  "eu1",
						service: "linksharing",
						request: "aws4_request",
					},
				},
				signedHeaders: []string{"host"},
				signature:     "...",
			},
			wantErr: false,
		},
	} {
		got, err := parseSigningInfo(tt.authorizationValue)

		if tt.wantErr {
			assert.Error(t, err, i)
		} else {
			require.NoError(t, err, i)
		}

		assert.Equal(t, tt.want, got, i)
	}
}

func TestParseCredential(t *testing.T) {
	for i, tt := range [...]struct {
		credential string
		want       parsedCredential
		wantScope  string
		wantErr    bool
	}{
		{
			credential: "",
			want:       parsedCredential{},
			wantErr:    true,
		},
		{
			credential: "Credential",
			want:       parsedCredential{},
			wantErr:    true,
		},
		{
			credential: "Credential=",
			want:       parsedCredential{},
			wantErr:    true,
		},
		{
			credential: "Credential=AccessKeyID",
			want:       parsedCredential{},
			wantErr:    true,
		},
		{
			credential: "Credential=AccessKeyID/20211229",
			want:       parsedCredential{},
			wantErr:    true,
		},
		{
			credential: "Credential=AccessKeyID/20211229/eu1",
			want:       parsedCredential{},
			wantErr:    true,
		},
		{
			credential: "Credential=AccessKeyID/20211229/eu1/linksharing",
			want:       parsedCredential{},
			wantErr:    true,
		},
		{
			credential: "Credential=AccessKeyID/Wed Dec 29 01:07:45 CET 2021/eu1/linksharing/aws4_request",
			want:       parsedCredential{},
			wantErr:    true,
		},
		{
			credential: "Credential=AccessKeyID/20211229/eu1/s3/aws4_request",
			want:       parsedCredential{},
			wantErr:    true,
		},
		{
			credential: "Credential=AccessKeyID/20211229/eu1/linksharing/???",
			want:       parsedCredential{},
			wantErr:    true,
		},
		{
			credential: "Credential=////",
			want:       parsedCredential{},
			wantErr:    true,
		},
		{
			credential: "Test=AccessKeyID/20211229/eu1/linksharing/aws4_request",
			want:       parsedCredential{},
			wantErr:    true,
		},
		{
			credential: "Credential=AccessKeyID/20211229/eu1/linksharing/aws4_request",
			want: parsedCredential{
				accessKeyID: "AccessKeyID",
				scope: struct {
					date                     time.Time
					region, service, request string
				}{
					date:    mustParseTime("20060102", "20211229"),
					region:  "eu1",
					service: "linksharing",
					request: "aws4_request",
				},
			},
			wantScope: "20211229/eu1/linksharing/aws4_request",
			wantErr:   false,
		},
	} {
		got, err := parseCredential(tt.credential)

		if tt.wantErr {
			assert.Error(t, err, i)
		} else {
			require.NoError(t, err, i)
		}

		if !tt.wantErr {
			assert.Equal(t, tt.wantScope, got.buildScope(), i)
		}

		assert.Equal(t, tt.want, got, i)
	}
}

func mustParseTime(layout, value string) time.Time {
	t, err := time.Parse(layout, value)
	if err != nil {
		panic(err)
	}
	return t
}

func TestParseSignedHeaders(t *testing.T) {
	for i, tt := range [...]struct {
		signedHeaders string
		want          []string
		wantErr       bool
	}{
		{
			signedHeaders: "",
			want:          nil,
			wantErr:       true,
		},
		{
			signedHeaders: "SignedHeaders",
			want:          nil,
			wantErr:       true,
		},
		{
			signedHeaders: "SignedHeaders=",
			want:          nil,
			wantErr:       true,
		},
		{
			signedHeaders: "SignedHeaders=;",
			want:          nil,
			wantErr:       true,
		},
		{
			signedHeaders: "SignedHeaders=test",
			want:          nil,
			wantErr:       true,
		},
		{
			signedHeaders: "SignedHeaders=test;",
			want:          nil,
			wantErr:       true,
		},
		{
			signedHeaders: "Test=host",
			want:          nil,
			wantErr:       true,
		},
		{
			signedHeaders: "Test=host;",
			want:          nil,
			wantErr:       true,
		},
		{
			signedHeaders: "SignedHeaders=host",
			want:          []string{"host"},
			wantErr:       false,
		},
		{
			signedHeaders: "SignedHeaders=host;",
			want:          []string{"host", ""},
			wantErr:       false,
		},
		{
			signedHeaders: "SignedHeaders=test;host",
			want:          []string{"test", "host"},
			wantErr:       false,
		},
		{
			signedHeaders: "SignedHeaders=test;host;",
			want:          []string{"test", "host", ""},
			wantErr:       false,
		},
	} {
		got, err := parseSignedHeaders(tt.signedHeaders)

		if tt.wantErr {
			assert.Error(t, err, i)
		} else {
			require.NoError(t, err, i)
		}

		assert.Equal(t, tt.want, got, i)
	}
}

func TestParseSignature(t *testing.T) {
	for i, tt := range [...]struct {
		signature string
		want      string
		wantErr   bool
	}{
		{
			signature: "",
			want:      "",
			wantErr:   true,
		},
		{
			signature: "Signature",
			want:      "",
			wantErr:   true,
		},
		{
			signature: "Signature=",
			want:      "",
			wantErr:   true,
		},
		{
			signature: "Test=test",
			want:      "",
			wantErr:   true,
		},
		{
			signature: "Signature=test",
			want:      "test",
			wantErr:   false,
		},
	} {
		got, err := parseSignature(tt.signature)

		if tt.wantErr {
			assert.Error(t, err, i)
		} else {
			require.NoError(t, err, i)
		}

		assert.Equal(t, tt.want, got, i)
	}
}
