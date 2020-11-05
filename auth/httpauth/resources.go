// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package httpauth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"

	"github.com/btcsuite/btcutil/base58"

	"storj.io/stargate/auth"
)

// Resources wrap a database and expose methods over HTTP.
type Resources struct {
	db        *auth.Database
	endpoint  string
	authToken string

	handler http.Handler
	id      *Arg
}

// New constructs Resources for some database.
func New(db *auth.Database, endpoint, authToken string) *Resources {
	res := &Resources{
		db:        db,
		endpoint:  endpoint,
		authToken: authToken,

		id: new(Arg),
	}

	res.handler = Dir{
		"/v1": Dir{
			"/access": Dir{
				"": Method{
					"POST": http.HandlerFunc(res.newAccess),
				},
				"*": res.id.Capture(Dir{
					"": Method{
						"GET":    http.HandlerFunc(res.getAccess),
						"DELETE": http.HandlerFunc(res.deleteAccess),
					},
					"/invalid": Dir{
						"": Method{
							"PUT": http.HandlerFunc(res.invalidateAccess),
						},
					},
				}),
			},
		},
	}

	return res
}

// ServeHTTP makes Resources an http.Handler.
func (res *Resources) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	res.handler.ServeHTTP(w, req)
}

func (res *Resources) newAccess(w http.ResponseWriter, req *http.Request) {
	var request struct {
		AccessGrant string `json:"access_grant"`
		Public      bool   `json:"public"`
	}

	if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var key auth.EncryptionKey
	if _, err := rand.Read(key[:]); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	secretKey, err := res.db.Put(req.Context(), key, request.AccessGrant, request.Public)
	if err != nil {
		http.Error(w, "error storing request in database", http.StatusInternalServerError)
		return
	}

	var response struct {
		AccessKeyID string `json:"access_key_id"`
		SecretKey   string `json:"secret_key"`
		Endpoint    string `json:"endpoint"`
	}

	response.AccessKeyID = base58.CheckEncode(key[:], auth.VersionAccessKeyID)
	response.SecretKey = base58.CheckEncode(secretKey, auth.VersionSecretKey)
	response.Endpoint = res.endpoint

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (res *Resources) requestAuthorized(req *http.Request) bool {
	auth := req.Header.Get("Authorization")
	return subtle.ConstantTimeCompare([]byte(auth), []byte("Bearer "+res.authToken)) == 1
}

func (res *Resources) getAccess(w http.ResponseWriter, req *http.Request) {
	if !res.requestAuthorized(req) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	encryptionKeyBytes, version, err := base58.CheckDecode(res.id.Value(req.Context()))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(encryptionKeyBytes) != len(auth.EncryptionKey{}) {
		http.Error(w, "invalid access key id length", http.StatusBadRequest)
		return
	}
	if version != auth.VersionAccessKeyID {
		http.Error(w, "unexpected decoded version", http.StatusBadRequest)
		return
	}

	var key auth.EncryptionKey
	copy(key[:], encryptionKeyBytes)

	accessGrant, public, secretKey, err := res.db.Get(req.Context(), key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var response struct {
		AccessGrant string `json:"access_grant"`
		SecretKey   string `json:"secret_key"`
		Public      bool   `json:"public"`
	}

	response.AccessGrant = accessGrant
	response.SecretKey = base58.CheckEncode(secretKey, auth.VersionSecretKey)
	response.Public = public

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (res *Resources) deleteAccess(w http.ResponseWriter, req *http.Request) {
	if !res.requestAuthorized(req) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	encryptionKeyBytes, version, err := base58.CheckDecode(res.id.Value(req.Context()))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(encryptionKeyBytes) != len(auth.EncryptionKey{}) {
		http.Error(w, "invalid access key id length", http.StatusBadRequest)
		return
	}
	if version != auth.VersionAccessKeyID {
		http.Error(w, "unexpected decoded version", http.StatusBadRequest)
		return
	}

	var key auth.EncryptionKey
	copy(key[:], encryptionKeyBytes)

	if err := res.db.Delete(req.Context(), key); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, "{}")
}

func (res *Resources) invalidateAccess(w http.ResponseWriter, req *http.Request) {
	if !res.requestAuthorized(req) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	encryptionKeyBytes, version, err := base58.CheckDecode(res.id.Value(req.Context()))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(encryptionKeyBytes) != len(auth.EncryptionKey{}) {
		http.Error(w, "invalid access key id length", http.StatusBadRequest)
		return
	}
	if version != auth.VersionAccessKeyID {
		http.Error(w, "unexpected decoded version", http.StatusBadRequest)
		return
	}

	var key auth.EncryptionKey
	copy(key[:], encryptionKeyBytes)

	var request struct {
		Reason string `json:"reason"`
	}

	if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := res.db.Invalidate(req.Context(), key, request.Reason); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, "{}")
}
