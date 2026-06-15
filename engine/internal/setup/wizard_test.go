package setup

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// newTestWizard builds a wizard with a scripted reader, a buffer sink, and a
// constant token so no TTY is needed.
func newTestWizard(input, token string, probe ProbeFunc) (*Wizard, *bytes.Buffer) {
	var out bytes.Buffer
	w := &Wizard{
		In:         strings.NewReader(input),
		Out:        &out,
		Probe:      probe,
		ReadSecret: func() (string, error) { return token, nil },
		MaxRetries: 3,
	}
	return w, &out
}

func TestMenuLive(t *testing.T) {
	w, _ := newTestWizard("1\n", "", nil)
	choice, err := w.Menu()
	if err != nil {
		t.Fatalf("Menu: %v", err)
	}
	if choice != ChoiceLive {
		t.Fatalf("choice = %v, want ChoiceLive", choice)
	}
}

func TestMenuDemo(t *testing.T) {
	w, _ := newTestWizard("2\n", "", nil)
	choice, err := w.Menu()
	if err != nil {
		t.Fatalf("Menu: %v", err)
	}
	if choice != ChoiceDemo {
		t.Fatalf("choice = %v, want ChoiceDemo", choice)
	}
}

func TestMenuRepromptsOnJunk(t *testing.T) {
	w, out := newTestWizard("x\n1\n", "", nil)
	choice, err := w.Menu()
	if err != nil {
		t.Fatalf("Menu: %v", err)
	}
	if choice != ChoiceLive {
		t.Fatalf("choice = %v, want ChoiceLive", choice)
	}
	if !strings.Contains(out.String(), "Please enter 1 or 2") {
		t.Errorf("expected a re-prompt message, got:\n%s", out.String())
	}
}

func TestRunHappyPath(t *testing.T) {
	const token = "super-secret-token"
	var probed struct {
		url, token string
		insecure   bool
	}
	probe := func(url, tok string, insecure bool) error {
		probed.url, probed.token, probed.insecure = url, tok, insecure
		return nil
	}
	// URL (accept default via blank line), then insecure = y.
	w, out := newTestWizard("\ny\n", token, probe)
	c, err := w.Run()
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if c.SplunkURL != defaultSplunkURL {
		t.Errorf("URL = %q, want default %q", c.SplunkURL, defaultSplunkURL)
	}
	if c.SplunkToken != token {
		t.Errorf("token = %q, want %q", c.SplunkToken, token)
	}
	if !c.SplunkInsecure {
		t.Errorf("insecure = false, want true")
	}
	if probed.token != token || probed.url != defaultSplunkURL || !probed.insecure {
		t.Errorf("probe received %+v, want url=%q token=%q insecure=true", probed, defaultSplunkURL, token)
	}
	// The token must never be echoed to the output.
	if strings.Contains(out.String(), token) {
		t.Errorf("token leaked into wizard output:\n%s", out.String())
	}
}

func TestRunRetriesThenSucceeds(t *testing.T) {
	calls := 0
	probe := func(string, string, bool) error {
		calls++
		if calls == 1 {
			return errors.New("connection refused")
		}
		return nil
	}
	// Two full passes: blank URL + "n" insecure, twice.
	w, _ := newTestWizard("\nn\n\nn\n", "tok", probe)
	if _, err := w.Run(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if calls != 2 {
		t.Fatalf("probe calls = %d, want 2", calls)
	}
}

func TestRunGivesUp(t *testing.T) {
	probe := func(string, string, bool) error { return errors.New("nope") }
	// Enough scripted lines to exhaust MaxRetries (3 passes of URL + insecure).
	w, _ := newTestWizard("\nn\n\nn\n\nn\n", "tok", probe)
	if _, err := w.Run(); err == nil {
		t.Fatal("Run succeeded, want error after exhausting retries")
	}
}

func TestValidateSplunkURL(t *testing.T) {
	good := []string{"https://localhost:8089", "http://splunk:8089", "https://10.0.0.5:8089/"}
	for _, s := range good {
		if err := validateSplunkURL(s); err != nil {
			t.Errorf("validateSplunkURL(%q) = %v, want nil", s, err)
		}
	}
	bad := []string{"", "localhost:8089", "ftp://x", "https://"}
	for _, s := range bad {
		if err := validateSplunkURL(s); err == nil {
			t.Errorf("validateSplunkURL(%q) = nil, want error", s)
		}
	}
}
