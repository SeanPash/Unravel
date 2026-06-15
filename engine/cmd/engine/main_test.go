package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// TestDiscoverTimelines guards against a recurrence of the replay-mode startup
// crash. The WebSocket-message fixture chain-phishing.json once lived at the
// testdata root and matched the chain-*.json glob, killing the mock source with
// "no parseable timestamp". It now lives under testdata/ws/, which
// discoverTimelines must skip, leaving only the real event timeline.
func TestDiscoverTimelines(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata")
	got, err := discoverTimelines(dir)
	if err != nil {
		t.Fatalf("discoverTimelines(%q): %v", dir, err)
	}
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 timeline, got %d: %v", len(got), got)
	}
	if base := filepath.Base(got[0]); base != "chain-phishing-events.json" {
		t.Fatalf("expected chain-phishing-events.json, got %q", base)
	}
	for _, p := range got {
		if filepath.Base(p) == "chain-phishing.json" {
			t.Fatalf("WebSocket fixture chain-phishing.json must not be discovered as a timeline: %v", got)
		}
	}
}

// TestResolveGeminiKeyPrecedence verifies the embedded key is only a last resort:
// a key already present (from the --gemini-key flag or GEMINI_API_KEY env, both
// resolved into cfg.apiKey by parseFlags) always wins.
func TestResolveGeminiKeyPrecedence(t *testing.T) {
	orig := embeddedGeminiKey
	t.Cleanup(func() { embeddedGeminiKey = orig })

	cases := []struct {
		name     string
		existing string // cfg.apiKey after parseFlags (flag-or-env)
		embedded string
		want     string
	}{
		{"flag or env beats embedded", "from-flag-or-env", "embedded", "from-flag-or-env"},
		{"embedded fills empty", "", "embedded", "embedded"},
		{"empty stays empty", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			embeddedGeminiKey = tc.embedded
			cfg := config{apiKey: tc.existing}
			resolveGeminiKey(&cfg)
			if cfg.apiKey != tc.want {
				t.Errorf("apiKey = %q, want %q", cfg.apiKey, tc.want)
			}
		})
	}
}

func TestIsSetupSubcommand(t *testing.T) {
	if !isSetupSubcommand([]string{"setup"}) {
		t.Error("isSetupSubcommand([setup]) = false, want true")
	}
	if !isSetupSubcommand([]string{"setup", "--ignored"}) {
		t.Error("isSetupSubcommand([setup --ignored]) = false, want true")
	}
	for _, args := range [][]string{nil, {}, {"--mode=live"}, {"replay"}, {"--setup"}} {
		if isSetupSubcommand(args) {
			t.Errorf("isSetupSubcommand(%v) = true, want false", args)
		}
	}
}

func TestBrowserHost(t *testing.T) {
	cases := map[string]string{
		"":          "127.0.0.1",
		"0.0.0.0":   "127.0.0.1",
		"127.0.0.1": "127.0.0.1",
		"localhost": "localhost",
		"::":        "[::1]",
		"::1":       "[::1]",
		"10.0.0.5":  "10.0.0.5",
	}
	for bind, want := range cases {
		if got := browserHost(bind); got != want {
			t.Errorf("browserHost(%q) = %q, want %q", bind, got, want)
		}
	}
}

// TestCheckSplunk exercises the connectivity check the wizard relies on, and
// asserts that error text never includes the bearer token.
func TestCheckSplunk(t *testing.T) {
	const token = "secret-bearer-token"

	t.Run("ok", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"generator":{}}`))
		}))
		defer srv.Close()
		if err := checkSplunk(config{splunkURL: srv.URL, splunkToken: token}, nil); err != nil {
			t.Fatalf("checkSplunk = %v, want nil", err)
		}
	})

	t.Run("unauthorized", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer srv.Close()
		err := checkSplunk(config{splunkURL: srv.URL, splunkToken: token}, nil)
		if err == nil {
			t.Fatal("checkSplunk = nil, want error")
		}
		if strings.Contains(err.Error(), token) {
			t.Errorf("error text leaked the token: %v", err)
		}
	})

	t.Run("unreachable", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		url := srv.URL
		srv.Close() // nothing is listening now
		if err := checkSplunk(config{splunkURL: url, splunkToken: token}, nil); err == nil {
			t.Fatal("checkSplunk against a closed server = nil, want error")
		}
	})
}
