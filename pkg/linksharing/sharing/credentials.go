// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/zeebo/errs"

	"storj.io/gateway-mt/pkg/errdata"
	"storj.io/gateway-mt/pkg/trustedip"
	"storj.io/uplink"
)

type credentialsCV struct{}

type credentials struct {
	serializedAccess string
	access           *uplink.Access
	hostingRoot      string
	hostingTLS       bool
	hostingHost      string
	err              error
}

func credentialsFromContext(ctx context.Context) *credentials {
	creds, ok := ctx.Value(credentialsCV{}).(*credentials)
	if !ok || creds == nil {
		creds = &credentials{err: errdata.WithStatus(errs.New("access missing"), http.StatusBadRequest)}
	}
	return creds
}

// CredentialsHandler retrieves and saves credentials as a context value.
func (h *Handler) CredentialsHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// don't try and get credentials for requests that don't need them.
		if strings.HasPrefix(r.URL.Path, "/static/") || strings.HasPrefix(r.URL.Path, "/health/process") {
			next.ServeHTTP(w, r)
			return
		}

		var err error
		var creds credentials
		ctx := r.Context()
		defer mon.TaskNamed("CredentialsHandler")(&ctx)(&err)

		ourDomain, err := isDomainOurs(r.Host, h.urlBases)
		if err != nil {
			creds.err = err
			next.ServeHTTP(w, reqWithCredentials(ctx, r, &creds))
			return
		}

		if ourDomain {
			creds, err = h.standardCredentials(ctx, r)
		} else {
			creds, err = h.hostingCredentials(ctx, r)
		}
		if err != nil {
			creds.err = err
		}
		next.ServeHTTP(w, reqWithCredentials(ctx, r, &creds))
	})
}

func reqWithCredentials(ctx context.Context, r *http.Request, creds *credentials) *http.Request {
	return r.WithContext(context.WithValue(ctx, credentialsCV{}, creds))
}

func (h *Handler) hostingCredentials(ctx context.Context, r *http.Request) (creds credentials, err error) {
	defer mon.Task()(&ctx)(&err)

	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		var aerr *net.AddrError
		if errors.As(err, &aerr) && aerr.Err == "missing port in address" {
			host = r.Host
		} else {
			return creds, errdata.WithStatus(err, http.StatusBadRequest)
		}
	}

	result, err := h.txtRecords.FetchAccessForHost(ctx, host, trustedip.GetClientIP(h.trustedClientIPsList, r))
	if err != nil {
		return creds, errdata.WithAction(err, "fetch access")
	}

	return credentials{
		serializedAccess: result.SerializedAccess,
		access:           result.Access,
		hostingRoot:      result.Root,
		hostingTLS:       result.TLS,
		hostingHost:      host,
	}, nil
}

func (h *Handler) standardCredentials(ctx context.Context, r *http.Request) (creds credentials, err error) {
	defer mon.Task()(&ctx)(&err)

	path := strings.TrimPrefix(r.URL.Path, "/")
	var serializedAccess string
	parts := strings.SplitN(path, "/", 3)
	switch len(parts) {
	case 0:
		return creds, errs.New("unreachable")
	case 1:
		if parts[0] == "" {
			return creds, errdata.WithStatus(errs.New("missing access"), http.StatusBadRequest)
		}
		return creds, errdata.WithStatus(errs.New("missing bucket"), http.StatusBadRequest)
	case 2:
		serializedAccess = parts[1]
	default:
		serializedAccess = parts[1]
	}

	// TODO(artur): make signedAccessValidityTolerance a configuration attribute.
	access, err := parseAccess(ctx, r, serializedAccess, 15*time.Minute, h.authClient, trustedip.GetClientIP(h.trustedClientIPsList, r))
	if err != nil {
		return creds, err
	}

	return credentials{
		serializedAccess: serializedAccess,
		access:           access,
	}, nil
}
