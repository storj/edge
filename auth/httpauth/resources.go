// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package httpauth

import (
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
	http.Error(w, "not implemented", http.StatusInternalServerError)
}

func (res *Resources) getAccess(w http.ResponseWriter, req *http.Request) {
	http.Error(w, "not implemented", http.StatusInternalServerError)
}

func (res *Resources) deleteAccess(w http.ResponseWriter, req *http.Request) {
	http.Error(w, "not implemented", http.StatusInternalServerError)
}

func (res *Resources) invalidateAccess(w http.ResponseWriter, req *http.Request) {
	http.Error(w, "not implemented", http.StatusInternalServerError)
}
