// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package httpauth

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync/atomic"

	"go.uber.org/zap"

	"storj.io/common/memory"
	"storj.io/gateway-mt/pkg/auth/authdb"
)

// Resources wrap a database and expose methods over HTTP.
type Resources struct {
	db        *authdb.Database
	endpoint  *url.URL
	authToken []string

	handler       http.Handler
	id            *Arg
	postSizeLimit memory.Size

	log *zap.Logger

	startup    int32
	inShutdown int32
}

// New constructs Resources for some database.
// If getAccessRL is nil then GetAccess endpoint won't be rate-limited.
func New(
	log *zap.Logger,
	db *authdb.Database,
	endpoint *url.URL,
	authToken []string,
	postSizeLimit memory.Size,
) *Resources {
	res := &Resources{
		db:        db,
		endpoint:  endpoint,
		authToken: authToken,

		id:            new(Arg),
		log:           log,
		postSizeLimit: postSizeLimit,
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
						"GET": http.HandlerFunc(res.getAccess),
					},
				}),
			},
		},
	}

	return res
}

// ServeHTTP makes Resources an http.Handler.
func (res *Resources) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Below is a pre-flight check to make sure we don't unnecessarily read what
	// we would throw away anyway.
	if req.ContentLength > res.postSizeLimit.Int64() {
		res.writeError(w, "ServeHTTP", "", http.StatusRequestEntityTooLarge)
		return
	}
	res.handler.ServeHTTP(w, req)
}

func (res *Resources) writeError(w http.ResponseWriter, method string, msg string, status int) {
	res.log.Info("writing error", zap.String("method", method), zap.String("msg", msg), zap.Int("status", status))
	if status >= http.StatusInternalServerError {
		msg = "" // message can contain sensitive details we don't want to expose
	}
	http.Error(w, msg, status)
}

// SetStartupDone sets the startup status flag to true indicating startup is complete.
func (res *Resources) SetStartupDone() {
	atomic.StoreInt32(&res.startup, 1)
}

// SetShutdown sets the inShutdown status flag to true indicating the server is shutting down.
func (res *Resources) SetShutdown() {
	atomic.StoreInt32(&res.inShutdown, 1)
}

// getStartup returns 200 when the service has finished initial start up
// processing and 503 Service Unavailable otherwise (e.g. established initial
// database connection, finished database migrations).
func (res *Resources) getStartup(w http.ResponseWriter, req *http.Request) {
	if atomic.LoadInt32(&res.startup) != 0 {
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

	// Confirm we have finished startup and are not shutting down.
	if atomic.LoadInt32(&res.startup) == 0 || atomic.LoadInt32(&res.inShutdown) != 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	// Confirm we can at a minimum reach the database.
	err := res.db.PingDB(req.Context())
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

	reader := http.MaxBytesReader(w, req.Body, res.postSizeLimit.Int64())
	if err := json.NewDecoder(reader).Decode(&request); err != nil {
		status := http.StatusUnprocessableEntity

		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			status = http.StatusRequestEntityTooLarge
		}

		res.writeError(w, "newAccess", err.Error(), status)
		return
	}

	var err error
	var key authdb.EncryptionKey
	if key, err = authdb.NewEncryptionKey(); err != nil {
		res.writeError(w, "newAccess/NewEncryptionKey", err.Error(), http.StatusInternalServerError)
		return
	}

	secretKey, err := res.db.Put(req.Context(), key, request.AccessGrant, request.Public)
	if err != nil {
		if authdb.ErrAccessGrant.Has(err) {
			res.writeError(w, "newAccess", err.Error(), http.StatusBadRequest)
			return
		}
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
	if len(res.authToken) == 0 {
		return true
	}
	for _, token := range res.authToken {
		if subtle.ConstantTimeCompare([]byte(auth), []byte("Bearer "+token)) == 1 {
			return true
		}
	}
	return false
}

func (res *Resources) getAccess(w http.ResponseWriter, req *http.Request) {
	res.log.Debug("getAccess request", zap.String("remote address", req.RemoteAddr))
	if !res.requestAuthorized(req) {
		res.writeError(w, "getAccess", "unauthorized", http.StatusUnauthorized)
		return
	}

	var key authdb.EncryptionKey
	err := key.FromBase32(res.id.Value(req.Context()))
	if err != nil {
		res.writeError(w, "getAccess", err.Error(), http.StatusBadRequest)
		return
	}

	accessGrant, public, secretKey, err := res.db.Get(req.Context(), key)
	if err != nil {
		if authdb.NotFound.Has(err) || authdb.Invalid.Has(err) {
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
