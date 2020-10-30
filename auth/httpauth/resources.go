// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package httpauth

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"

	"storj.io/stargate/auth"
)

// Resources wrap a database and expose methods over HTTP.
type Resources struct {
	db      *auth.Database
	handler http.Handler
	id      *Arg
}

// New constructs Resources for some database.
func New(db *auth.Database) *Resources {
	res := &Resources{
		db: db,
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
	}

	if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var key auth.EncryptionKey // TODO: generate this

	secretKey, err := res.db.Put(req.Context(), key, request.AccessGrant)
	if err != nil {
		http.Error(w, "error storing request in database", http.StatusInternalServerError)
		return
	}

	var response struct {
		AccessKeyID string `json:"access_key_id"`
		SecretKey   string `json:"secret_key"`
	}

	response.AccessKeyID = hex.EncodeToString(key[:])  // TODO: better encoding
	response.SecretKey = hex.EncodeToString(secretKey) // TODO: encoding?

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (res *Resources) getAccess(w http.ResponseWriter, req *http.Request) {
	encryptionKeyBytes, err := hex.DecodeString(res.id.Value(req.Context()))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else if len(encryptionKeyBytes) != len(auth.EncryptionKey{}) {
		http.Error(w, "invalid access key id length", http.StatusBadRequest)
		return
	}

	var key auth.EncryptionKey
	copy(key[:], encryptionKeyBytes)

	accessGrant, secretKey, err := res.db.Get(req.Context(), key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var response struct {
		AccessGrant string `json:"access_grant"`
		SecretKey   string `json:"secret_key"`
	}

	response.AccessGrant = accessGrant
	response.SecretKey = hex.EncodeToString(secretKey) // TODO: encoding?

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (res *Resources) deleteAccess(w http.ResponseWriter, req *http.Request) {
	encryptionKeyBytes, err := hex.DecodeString(res.id.Value(req.Context()))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else if len(encryptionKeyBytes) != len(auth.EncryptionKey{}) {
		http.Error(w, "invalid access key id length", http.StatusBadRequest)
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
	encryptionKeyBytes, err := hex.DecodeString(res.id.Value(req.Context()))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else if len(encryptionKeyBytes) != len(auth.EncryptionKey{}) {
		http.Error(w, "invalid access key id length", http.StatusBadRequest)
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
