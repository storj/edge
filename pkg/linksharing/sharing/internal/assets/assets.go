// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package assets

import (
	"embed"
	"fmt"
	"io/fs"
)

//go:embed templates/*
var templates embed.FS

//go:embed static/*
var staticAssets embed.FS

// FS contains filesystems for HTML templates and static web assets.
type FS struct {
	Templates fs.FS
	Static    fs.FS
}

// GetFS returns an FS initialized with filesystems for embedded web assets.
func GetFS() (FS, error) {
	templateFS, err := fs.Sub(templates, "templates")
	if err != nil {
		return FS{}, fmt.Errorf("error embedding templates: %w", err)
	}

	staticFS, err := fs.Sub(staticAssets, "static")
	if err != nil {
		return FS{}, fmt.Errorf("error embedding static assets: %w", err)
	}

	return FS{Templates: templateFS, Static: staticFS}, nil
}
