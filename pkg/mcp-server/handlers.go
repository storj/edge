// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package mcpserver

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/spacemonkeygo/monkit/v3"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"storj.io/edge/internal/register"
	"storj.io/edge/pkg/authclient"
	"storj.io/edge/pkg/errdata"
)

var mon = monkit.Package()

// Handler is an MCP handler.
type Handler struct {
	authClient *authclient.AuthClient
	log        *zap.Logger
}

// Register handles user's registering their access grant and responding with a bearer token.
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)

	var request struct {
		AccessGrant string `json:"access_grant"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON: %s", err), http.StatusUnprocessableEntity)
		return
	}

	if request.AccessGrant == "" {
		http.Error(w, "access_grant is required", http.StatusBadRequest)
		return
	}

	registerResp, err := register.Access(ctx, h.authClient.BaseURL, request.AccessGrant, false, []string{"mcp"})
	if err != nil {
		logError(h.log, err)
		http.Error(w, authErrorMessage(err), errdata.GetStatus(err, http.StatusInternalServerError))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(struct {
		BearerToken string `json:"bearer_token"`
	}{
		BearerToken: registerResp.AccessKeyID,
	}); err != nil {
		http.Error(w, fmt.Sprintf("failed to encode response: %s", err), http.StatusInternalServerError)
	}
}

// authErrorMessage writes an appropriate error message to the user if it's related to the user
// providing an invalid access grant. Generic errors are shown for any status from authservice
// we don't recognise as it may contain internal information the user shouldn't see.
func authErrorMessage(err error) string {
	switch errdata.GetStatus(err, 0) {
	case http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity, http.StatusBadRequest:
		return "credentials error: " + err.Error()
	default:
		return "failed to register access grant"
	}
}

func logError(log *zap.Logger, err error) {
	var level zapcore.Level

	switch errdata.GetStatus(err, http.StatusOK) {
	case http.StatusUnauthorized, http.StatusBadRequest:
		level = zap.DebugLevel
	case http.StatusInternalServerError:
		level = zap.ErrorLevel
	default:
		level = zap.ErrorLevel
	}

	ce := log.Check(level, "system")
	if ce != nil {
		ce.Write(zap.String("error", err.Error()))
	}
}
