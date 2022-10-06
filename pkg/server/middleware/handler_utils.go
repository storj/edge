package middleware

import (
	"fmt"
	"net/http"
	"time"

	xhttp "storj.io/minio/cmd/http"
)

func mustGetRequestID(t time.Time) string {
	return fmt.Sprintf("%X", t.UnixNano())
}

// UTCNow - returns current UTC time.
func utcNow() time.Time {
	return time.Now().UTC()
}

func AddRequestIds(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reusing the field x-amz-request-id to set unique request Ids for each request.
		w.Header().Set(xhttp.AmzRequestID, mustGetRequestID(utcNow()))
		h.ServeHTTP(w, r)

	})
}
