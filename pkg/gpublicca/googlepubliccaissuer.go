// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gpublicca

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/acme"
	"github.com/zeebo/errs"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// google public ca URLs.
const (
	GooglePublicCAProduction     = "https://dv.acme-v02.api.pki.goog/directory"
	GooglePublicCAStaging        = "https://dv.acme-v02.test-api.pki.goog/directory"
	googlePublicCAAPIBase        = "https://publicca.googleapis.com"
	googlePublicCAStagingAPIBase = "https://preprod-publicca.googleapis.com"
)

var (
	// Error is the error class for this package.
	Error errs.Class = "gpublicca"
	// Interface guards.
	_ certmagic.PreChecker = (*GooglePublicCAIssuer)(nil)
	_ certmagic.Issuer     = (*GooglePublicCAIssuer)(nil)
	_ certmagic.Revoker    = (*GooglePublicCAIssuer)(nil)
)

// GooglePublicCAIssuer makes an ACME issuer for getting certificates
// from GooglePublicCA by automatically generating EAB credentials.
//
// This issuer is only needed for automatic generation of EAB
// credentials. If manually configuring EAB credentials,
// the standard ACMEIssuer may be used if desired.
type GooglePublicCAIssuer struct {
	*certmagic.ACMEIssuer

	// service account with publicca.externalAccountKeyCreator IAM role.
	jsonKey []byte
}

// New initializes a google public CA ACME issuer.
func New(acmeIss *certmagic.ACMEIssuer, key []byte) *GooglePublicCAIssuer {
	iss := GooglePublicCAIssuer{
		ACMEIssuer: acmeIss,
		jsonKey:    key,
	}
	if iss.ACMEIssuer.CA == "" {
		iss.ACMEIssuer.CA = GooglePublicCAProduction
	}
	if iss.ACMEIssuer.NewAccountFunc == nil {
		iss.ACMEIssuer.NewAccountFunc = iss.newAccountCallback
	}
	return &iss
}

// newAccountCallback generates EAB if not already provided. It also sets a valid default contact on the account if not set.
func (iss *GooglePublicCAIssuer) newAccountCallback(ctx context.Context, acmeIss *certmagic.ACMEIssuer, acct acme.Account) (acme.Account, error) {
	if acmeIss.ExternalAccount != nil {
		return acct, nil
	}
	var err error
	acmeIss.ExternalAccount, acct, err = iss.generateEABCredentials(ctx, acct)
	return acct, err
}

// generateEABCredentials generates EAB credentials using the API key if provided,
// otherwise using the primary contact email on the issuer. If an email is not set
// on the issuer, a default generic email is used.
func (iss *GooglePublicCAIssuer) generateEABCredentials(ctx context.Context, acct acme.Account) (*acme.EAB, acme.Account, error) {
	email := iss.Email
	if len(acct.Contact) == 0 {
		// we borrow the email from config or the default email, so ensure it's saved with the account
		acct.Contact = []string{"mailto:" + email}
	}

	apiBase := googlePublicCAAPIBase
	if iss.CA == GooglePublicCAStaging {
		apiBase = googlePublicCAStagingAPIBase
	}

	c, err := google.CredentialsFromJSON(ctx, iss.jsonKey, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return nil, acct, Error.New("parsing service account key file: %w", err)
	}
	client := oauth2.NewClient(ctx, c.TokenSource)
	endpoint := fmt.Sprintf("%s/v1beta1/projects/%s/locations/global/externalAccountKeys", apiBase, c.ProjectID)

	reqData := struct {
		Name      string `json:"name"`
		KeyID     string `json:"keyId"`
		B64MacKey string `json:"b64MacKey"`
	}{}
	b, err := json.Marshal(reqData)
	if err != nil {
		return nil, acct, Error.New("encoding EAB request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBuffer(b))
	if err != nil {
		return nil, acct, Error.New("forming request: %w", err)
	}

	req.Header.Set("User-Agent", certmagic.UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, acct, Error.New("preforming EAB credentials request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if err := json.NewDecoder(resp.Body).Decode(&reqData); err != nil {
		return nil, acct, Error.New("decoding EAB resonse: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, acct, Error.New("EAB request failed: HTTP %d", resp.StatusCode)
	}

	b64MacKey, err := base64.URLEncoding.DecodeString(reqData.B64MacKey)
	if err != nil {
		return nil, acct, Error.New("decoding MacKey %w", err)
	}

	return &acme.EAB{
		KeyID:  reqData.KeyID,
		MACKey: string(b64MacKey),
	}, acct, nil
}

// PreCheck implements the certmagic.PreChecker interface.
func (iss *GooglePublicCAIssuer) PreCheck(ctx context.Context, names []string, interactive bool) error {
	// Certmagic doesn't do this check for the google public ca yet so do it here
	for _, name := range names {
		if !certmagic.SubjectQualifiesForPublicCert(name) {
			return Error.New("subject does not qualify for a public certificate: %s", name)
		}
	}
	return iss.ACMEIssuer.PreCheck(ctx, names, interactive)
}
