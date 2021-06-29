// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package httpauth

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"

	"go.uber.org/zap"

	"storj.io/gateway-mt/auth"
)

// Resources wrap a database and expose methods over HTTP.
type Resources struct {
	db        *auth.Database
	endpoint  *url.URL
	authToken string

	handler http.Handler
	id      *Arg

	log *zap.Logger

	mu      sync.Mutex
	startup bool
}

// New constructs Resources for some database.
func New(log *zap.Logger, db *auth.Database, endpoint *url.URL, authToken string) *Resources {
	res := &Resources{
		db:        db,
		endpoint:  endpoint,
		authToken: authToken,

		id:  new(Arg),
		log: log,
	}

	res.handler = Dir{
		"/v1": Dir{
			"/health": Dir{
				"/startup": Dir{
					"": Method{
						"GET": http.HandlerFunc(res.getStartup),
					},
				},
				"/live": Dir{
					"": Method{
						"GET": http.HandlerFunc(res.getLive),
					},
				},
			},
			"/access": Dir{
				"": Method{
					"POST":    http.HandlerFunc(res.newAccess),
					"OPTIONS": http.HandlerFunc(res.newAccessCORS),
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

func (res *Resources) writeError(w http.ResponseWriter, method string, msg string, status int) {
	res.log.Info("writing error", zap.String("method", method), zap.String("msg", msg), zap.Int("status", status))
	http.Error(w, msg, status)
}

// SetStartupDone sets the startup status flag to true indicating startup is complete.
func (res *Resources) SetStartupDone() {
	res.mu.Lock()
	defer res.mu.Unlock()

	res.startup = true
}

// getStartup returns 200 when the service has finished initial start up
// processing and 503 Service Unavailable otherwise (e.g. established initial
// database connection, finished database migrations).
func (res *Resources) getStartup(w http.ResponseWriter, req *http.Request) {
	res.mu.Lock()
	defer res.mu.Unlock()

	if res.startup {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
}

// getLive returns 200 when the service is able to process requests and 503
// Service Unavailable otherwise (e.g. this would return 503 if the database
// connection failed).
func (res *Resources) getLive(w http.ResponseWriter, req *http.Request) {
	res.log.Debug("getLive request", zap.String("remote address", req.RemoteAddr))

	res.mu.Lock()
	defer res.mu.Unlock()

	// Confirm we have finished startup.
	if !res.startup {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	// Confirm we can at a minimum reach the database.
	err := res.db.Ping(req.Context())
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (res *Resources) newAccess(w http.ResponseWriter, req *http.Request) {
	res.newAccessCORS(w, req)
	res.log.Debug("newAccess request", zap.String("remote address", req.RemoteAddr))
	var request struct {
		AccessGrant string `json:"access_grant"`
		Public      bool   `json:"public"`
	}

	if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
		res.writeError(w, "newAccess", err.Error(), http.StatusInternalServerError)
		return
	}

	var err error
	var key auth.EncryptionKey
	if key, err = auth.NewEncryptionKey(); err != nil {
		res.writeError(w, "newAccess", err.Error(), http.StatusInternalServerError)
		return
	}

	secretKey, err := res.db.Put(req.Context(), key, request.AccessGrant, request.Public)
	if err != nil {
		res.writeError(w, "newAccess", fmt.Sprintf("error storing request in database: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	var response struct {
		AccessKeyID string `json:"access_key_id"`
		SecretKey   string `json:"secret_key"`
		Endpoint    string `json:"endpoint"`
	}

	response.AccessKeyID = key.ToBase32()
	response.SecretKey = secretKey.ToBase32()
	response.Endpoint = res.endpoint.String()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (res *Resources) newAccessCORS(w http.ResponseWriter, req *http.Request) {
	// TODO: we should be checking req.Header.Get("Origin") against
	// an explicit allowlist and returning it here instead of "*" if it
	// matches, but this is okay for now.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers",
		"Content-Type, Accept, Accept-Language, Content-Language, Content-Length, Accept-Encoding")
}

func (res *Resources) requestAuthorized(req *http.Request) bool {
	auth := req.Header.Get("Authorization")
	return subtle.ConstantTimeCompare([]byte(auth), []byte("Bearer "+res.authToken)) == 1
}

func (res *Resources) getAccess(w http.ResponseWriter, req *http.Request) {
	res.log.Debug("getAccess request", zap.String("remote address", req.RemoteAddr))
	if !res.requestAuthorized(req) {
		res.writeError(w, "getAccess", "unauthorized", http.StatusUnauthorized)
		return
	}

	var key auth.EncryptionKey
	err := key.FromBase32(res.id.Value(req.Context()))
	if err != nil {
		res.writeError(w, "getAccess", err.Error(), http.StatusBadRequest)
		return
	}

	accessGrant, public, secretKey, err := res.db.Get(req.Context(), key)
	if err != nil {
		if auth.NotFound.Has(err) {
			res.writeError(w, "getAccess", err.Error(), http.StatusUnauthorized)
			return
		}
		res.writeError(w, "getAccess", err.Error(), http.StatusInternalServerError)
		return
	}

	var response struct {
		AccessGrant string `json:"access_grant"`
		SecretKey   string `json:"secret_key"`
		Public      bool   `json:"public"`
	}

	response.AccessGrant = accessGrant
	response.SecretKey = secretKey.ToBase32()
	response.Public = public

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (res *Resources) deleteAccess(w http.ResponseWriter, req *http.Request) {
	res.log.Debug("deleteAccess request", zap.String("remote address", req.RemoteAddr))
	if !res.requestAuthorized(req) {
		res.writeError(w, "deleteAccess", "unauthorized", http.StatusUnauthorized)
		return
	}

	var key auth.EncryptionKey
	err := key.FromBase32(res.id.Value(req.Context()))
	if err != nil {
		res.writeError(w, "deleteAccess", err.Error(), http.StatusBadRequest)
		return
	}

	if err := res.db.Delete(req.Context(), key); err != nil {
		res.writeError(w, "deleteAccess", err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, "{}")
}

func (res *Resources) invalidateAccess(w http.ResponseWriter, req *http.Request) {
	res.log.Debug("invalidateAccess request", zap.String("remote address", req.RemoteAddr))
	if !res.requestAuthorized(req) {
		res.writeError(w, "invalidateAccess", "unauthorized", http.StatusUnauthorized)
		return
	}

	var key auth.EncryptionKey
	err := key.FromBase32(res.id.Value(req.Context()))
	if err != nil {
		res.writeError(w, "invalidateAccess", err.Error(), http.StatusBadRequest)
		return
	}

	var request struct {
		Reason string `json:"reason"`
	}

	if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
		res.writeError(w, "invalidateAccess", err.Error(), http.StatusInternalServerError)
		return
	}

	if err := res.db.Invalidate(req.Context(), key, request.Reason); err != nil {
		res.writeError(w, "invalidateAccess", err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, "{}")
}
