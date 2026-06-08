package api

import (
	"io/fs"
	"testing"
)

func TestStaticFSIsNotNil(t *testing.T) {
	fsys := StaticFS()
	if fsys == nil {
		t.Fatal("StaticFS() returned nil")
	}
}

func TestStaticFSSubStripsStaticPrefix(t *testing.T) {
	fsys := StaticFS()
	// After fs.Sub, "static/" should not be a valid path in the returned FS.
	_, err := fs.Stat(fsys, "static")
	if err == nil {
		t.Error("StaticFS() still contains 'static' directory: fs.Sub was not applied")
	}
}
