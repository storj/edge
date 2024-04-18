// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package assets

import (
	"embed"
	"fmt"
	"io/fs"

	"storj.io/edge/pkg/linksharing/sharing"
)

//go:embed templates/*
var templates embed.FS

//go:embed static/*
var staticAssets embed.FS

// Load configures linksharing to use embedded web assets.
func Load() error {
	templateFS, err := fs.Sub(templates, "templates")
	if err != nil {
		return fmt.Errorf("error embedding templates: %w", err)
	}

	staticFS, err := fs.Sub(staticAssets, "static")
	if err != nil {
		return fmt.Errorf("error embedding static assets: %w", err)
	}

	sharing.Assets = sharing.AssetsFS{Templates: templateFS, Static: staticFS}

	return nil
}
