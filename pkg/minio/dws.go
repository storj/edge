package minio

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"

	xhttp "storj.io/minio/cmd/http"
)

const (
	Sep          = "/"
	VarKeyBucket = "bucket"
	VarKeyObject = "object"
)

func (h objectAPIHandlersWrapper) checkBucketExistence(r *http.Request) bool {
	w := &MockResponseWriter{}
	h.core.HeadBucketHandler(w, r)
	return w.GetStatusCode() == http.StatusOK
}

func (h objectAPIHandlersWrapper) getUserID(r *http.Request) (string, error) {
	return "very-unique-username-bucket-1", nil
}

func (h objectAPIHandlersWrapper) bucketNameIsAvailable(r *http.Request) (bool, error) {
	vars := mux.Vars(r)
	bucket := vars[VarKeyBucket]
	if bucket == "" {
		return false, nil
	}
	return true, nil
}

func (h objectAPIHandlersWrapper) bucketPrefixSubstitutionWithoutObject(w http.ResponseWriter, r *http.Request) error {
	vars := mux.Vars(r)
	userID, err := h.getUserID(r)
	if err != nil {
		writeErrorResponse(w, "user not found", http.StatusBadRequest)
		return fmt.Errorf("user not found")
	}
	vars[VarKeyBucket] = userID
	return nil
}

func (h objectAPIHandlersWrapper) bucketPrefixSubstitutionWithObject(w http.ResponseWriter, r *http.Request) error {
	vars := mux.Vars(r)
	bucket := vars[VarKeyBucket]
	userID, err := h.getUserID(r)
	if err != nil {
		writeErrorResponse(w, "user not found", http.StatusBadRequest)
		return fmt.Errorf("user not found")
	}
	vars[VarKeyBucket] = userID
	vars[VarKeyObject] = bucket
	return nil
}

func (h objectAPIHandlersWrapper) objectPrefixSubstitution(w http.ResponseWriter, r *http.Request) error {
	vars := mux.Vars(r)
	bucket := vars[VarKeyBucket]
	object := vars[VarKeyObject]
	userID, err := h.getUserID(r)
	if err != nil {
		writeErrorResponse(w, "user not found", http.StatusBadRequest)
		return fmt.Errorf("user not found")
	}
	vars[VarKeyBucket] = userID
	vars[VarKeyObject] = strings.Join([]string{bucket, object}, Sep)
	return nil
}

type MockResponseWriter struct {
	code int
}

func (m *MockResponseWriter) Header() http.Header {
	return http.Header{}
}

func (m *MockResponseWriter) Write([]byte) (int, error) {
	return 0, nil
}

func (m *MockResponseWriter) WriteHeader(statusCode int) {
	m.code = statusCode
}

func (m *MockResponseWriter) GetStatusCode() int {
	return m.code
}

func writeErrorResponse(w http.ResponseWriter, response string, statusCode int) {
	h := w.Header()
	h.Set(xhttp.ContentType, "text/plain")
	h.Set(xhttp.ContentLength, strconv.Itoa(len(response)))

	h.Set(xhttp.ServerInfo, "MinIO")
	h.Set(xhttp.AmzBucketRegion, "")
	h.Set(xhttp.AcceptRanges, "bytes")

	h.Del(xhttp.AmzServerSideEncryptionCustomerKey)
	h.Del(xhttp.AmzServerSideEncryptionCopyCustomerKey)
	h.Del(xhttp.AmzMetaUnencryptedContentLength)
	h.Del(xhttp.AmzMetaUnencryptedContentMD5)

	w.WriteHeader(statusCode)
	if response != "" {
		w.Write([]byte(response))
		w.(http.Flusher).Flush()
	}
}
