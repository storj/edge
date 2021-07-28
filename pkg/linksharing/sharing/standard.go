// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/zeebo/errs"
)

func (handler *Handler) handleStandard(ctx context.Context, w http.ResponseWriter, r *http.Request) (err error) {
	defer mon.Task()(&ctx)(&err)

	var pr parsedRequest
	path := strings.TrimPrefix(r.URL.Path, "/")
	switch {
	case strings.HasPrefix(path, "raw/"): // raw - just render the file
		path = path[len("raw/"):]
		pr.wrapDefault = false
	case strings.HasPrefix(path, "s/"): // wrap the file with a nice frame
		path = path[len("s/"):]
		pr.wrapDefault = true
	default: // backwards compatibility
		// preserve query params
		destination := (&url.URL{Path: "/s/" + path, RawQuery: r.URL.RawQuery}).String()
		http.Redirect(w, r, destination, http.StatusSeeOther)
		return nil
	}

	var serializedAccess string
	parts := strings.SplitN(path, "/", 3)
	switch len(parts) {
	case 0:
		return errs.New("unreachable")
	case 1:
		if parts[0] == "" {
			return WithStatus(errs.New("missing access"), http.StatusBadRequest)
		}
		return WithStatus(errs.New("missing bucket"), http.StatusBadRequest)
	case 2:
		serializedAccess = parts[0]
		pr.bucket = parts[1]
	default:
		serializedAccess = parts[0]
		pr.bucket = parts[1]
		pr.realKey = parts[2]
	}

	access, err := parseAccess(ctx, serializedAccess, handler.authConfig,
		getClientIP(handler.trustedClientIPsList, r),
	)
	if err != nil {
		return err
	}

	pr.access = access

	pr.visibleKey = pr.realKey
	pr.title = pr.bucket
	pr.root = breadcrumb{Prefix: pr.bucket, URL: "/s/" + serializedAccess + "/" + pr.bucket + "/"}

	return handler.present(ctx, w, r, &pr)
}
