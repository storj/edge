// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package httpauth

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"

	"go.uber.org/zap"

	"storj.io/common/memory"
	"storj.io/gateway-mt/pkg/auth/authdb"
)

// Resources wrap a database and expose methods over HTTP.
type Resources struct {
	db        *authdb.Database
	endpoint  *url.URL
	authToken string

	handler       http.Handler
	id            *Arg
	postSizeLimit memory.Size

	log *zap.Logger

	mu      sync.Mutex
	startup bool
}

// New constructs Resources for some database.
// If getAccessRL is nil then GetAccess endpoint won't be rate-limited.
func New(
	log *zap.Logger,
	db *authdb.Database,
	endpoint *url.URL,
	authToken string,
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
	startup := res.startup
	res.mu.Unlock()

	if startup {
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
	startup := res.startup
	res.mu.Unlock()

	// Confirm we have finished startup.
	if !startup {
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

		if checkRequestBodyTooLargeError(err) {
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

	// TODO: we need to differentiate between validation and genuine database
	// errors because we return 500s for, e.g. empty requests right now.
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

func checkRequestBodyTooLargeError(err error) bool {
	// TODO(artur): proper check after https://github.com/golang/go/issues/30715
	// is finally closed.
	return err.Error() == "http: request body too large"
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

	var key authdb.EncryptionKey
	err := key.FromBase32(res.id.Value(req.Context()))
	if err != nil {
		res.writeError(w, "getAccess", err.Error(), http.StatusBadRequest)
		return
	}

	accessGrant, public, secretKey, err := res.db.Get(req.Context(), key)
	if err != nil {
		if authdb.NotFound.Has(err) {
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
