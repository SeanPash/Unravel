package api

import (
	"embed"
	"io/fs"
)

//go:embed all:static
var staticFiles embed.FS

// StaticFS returns the embedded React production build rooted at index.html.
// During development the static/ directory holds only .gitkeep, so callers
// should treat an empty FS as "no UI bundled" rather than an error.
func StaticFS() (fs.FS, error) {
	return fs.Sub(staticFiles, "static")
}
