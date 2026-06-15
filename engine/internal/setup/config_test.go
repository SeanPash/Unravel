package setup

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	want := &Config{
		SplunkURL:      "https://splunk.example:8089",
		SplunkToken:    "secret-token",
		SplunkInsecure: true,
	}
	if err := Save(path, want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got == nil || *got != *want {
		t.Fatalf("round-trip mismatch: got %+v want %+v", got, want)
	}
}

func TestSavePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix file modes are advisory on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "config.json")
	if err := Save(path, &Config{SplunkURL: "https://x:8089", SplunkToken: "t"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("file mode = %o, want 600", perm)
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := di.Mode().Perm(); perm != 0o700 {
		t.Errorf("dir mode = %o, want 700", perm)
	}
}

func TestLoadNotExist(t *testing.T) {
	got, err := Load(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatalf("Load of missing file returned err: %v", err)
	}
	if got != nil {
		t.Fatalf("Load of missing file = %+v, want nil", got)
	}
}

func TestLoadCorrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}
	got, err := Load(path)
	if got != nil {
		t.Fatalf("Load of corrupt file = %+v, want nil", got)
	}
	if !errors.Is(err, ErrCorruptConfig) {
		t.Fatalf("Load of corrupt file err = %v, want ErrCorruptConfig", err)
	}
}

func TestConfigPath(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	// On Windows os.UserHomeDir reads USERPROFILE; keep this test unix-only.
	if runtime.GOOS == "windows" {
		t.Skip("HOME override not honored on Windows")
	}
	path, err := ConfigPath()
	if err != nil {
		t.Fatalf("ConfigPath: %v", err)
	}
	if !strings.HasSuffix(path, filepath.Join(".unravel", "config.json")) {
		t.Fatalf("ConfigPath = %q, want suffix .unravel/config.json", path)
	}
}
