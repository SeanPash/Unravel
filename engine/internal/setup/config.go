// Package setup implements Unravel's first-run setup wizard: an interactive
// front door that collects the Splunk connection details, validates them, and
// persists them to a local config file so a bare `unravel` invocation can launch
// straight into the live UI. It is pure terminal I/O plus a small JSON config;
// it holds no LLM calls and never touches the engine's ingest, graph, scoring,
// or chain-extraction stages.
package setup

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrCorruptConfig is returned by Load when the config file exists but cannot be
// decoded. Callers branch on it (errors.Is) to re-run the wizard rather than
// crash or silently clobber a file that may still hold a recoverable token.
var ErrCorruptConfig = errors.New("config file is present but unreadable")

// Config is the persisted Splunk connection. It is deliberately minimal: only
// what the wizard collects to bring up live mode. Everything else (search
// expression, AI key, HEC) stays on engine defaults or flags.
type Config struct {
	SplunkURL      string `json:"splunk_url"`
	SplunkToken    string `json:"splunk_token"`
	SplunkInsecure bool   `json:"splunk_insecure"`
}

// ConfigDir returns the per-user Unravel config directory (~/.unravel). It uses
// os.UserHomeDir so it honors $HOME on unix and %USERPROFILE% on Windows.
func ConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, ".unravel"), nil
}

// ConfigPath returns the path to the persisted config file (~/.unravel/config.json).
func ConfigPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

// Load reads and decodes the config at path. It distinguishes three states the
// caller cares about:
//
//   - file does not exist: returns (nil, nil), the "first run" signal.
//   - file exists but unreadable/permission: returns (nil, err).
//   - file exists but is not valid JSON: returns (nil, ErrCorruptConfig).
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrCorruptConfig, path, err)
	}
	return &c, nil
}

// Save writes c to path as indented JSON. The directory is created 0700 and the
// file is written 0600 because it holds a bearer token at rest. The write is
// atomic (temp file in the same directory, chmod, then rename) so a crash
// mid-write cannot leave a torn or world-readable file. File modes are advisory
// on Windows; we set them regardless and let the OS apply what it can.
func Save(path string, c *Config) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config dir %s: %w", dir, err)
	}
	// Tighten the dir mode explicitly: MkdirAll is subject to umask.
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("chmod config dir %s: %w", dir, err)
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}

	tmp, err := os.CreateTemp(dir, "config-*.json.tmp")
	if err != nil {
		return fmt.Errorf("create temp config: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if anything below fails before the rename.
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp config: %w", err)
	}
	// Set 0600 before the rename so there is no window where the final path is
	// readable by others.
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("chmod temp config: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("install config %s: %w", path, err)
	}
	return nil
}
