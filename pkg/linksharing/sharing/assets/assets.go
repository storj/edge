// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package assets

import (
	"embed"
	"io/fs"
)

//go:embed templates/* static/*
var data embed.FS

// FS loads the embedded assets.
func FS() fs.FS {
	return data
}
