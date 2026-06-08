package api

import (
	"embed"
	"io/fs"
	"log"
)

//go:embed all:static
var embeddedStatic embed.FS

// StaticFS returns the React production build embedded into the binary, rooted
// at the static/ directory so callers see index.html at the top level.
// Pass the result to NewServer; it is safe to call before the UI has been built
// (the FS will simply be empty aside from placeholder files).
func StaticFS() fs.FS {
	sub, err := fs.Sub(embeddedStatic, "static")
	if err != nil {
		log.Panicf("api: StaticFS: fs.Sub failed: %v", err)
	}
	return sub
}
