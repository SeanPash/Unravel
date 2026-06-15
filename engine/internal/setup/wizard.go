package setup

import (
	"bufio"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"golang.org/x/term"
)

// defaultSplunkURL mirrors the engine's --splunk-url default so an operator can
// accept it by pressing Enter.
const defaultSplunkURL = "https://localhost:8089"

// ProbeFunc validates connectivity to a Splunk instance. The wizard calls it
// after collecting inputs and re-prompts on error. Production wiring points this
// at the engine's startup connectivity check; tests pass a fake.
type ProbeFunc func(url, token string, insecure bool) error

// Choice is the top-level first-run menu result.
type Choice int

const (
	// ChoiceLive is "Connect to my Splunk" (runs the wizard, then live mode).
	ChoiceLive Choice = iota + 1
	// ChoiceDemo is "Try the demo" (replay mode, no setup persisted).
	ChoiceDemo
)

// Wizard drives the interactive setup flow. Every external interaction is an
// injectable field so the flow is unit-testable with no TTY, no Splunk, and no
// network: tests supply a scripted In, a buffer Out, a fake Probe, and a plain
// ReadSecret.
type Wizard struct {
	In         io.Reader              // input source; defaults to os.Stdin
	Out        io.Writer              // output sink; defaults to os.Stdout
	Probe      ProbeFunc              // connectivity check; nil accepts inputs as-is
	ReadSecret func() (string, error) // no-echo line read; nil uses x/term on os.Stdin
	MaxRetries int                    // bounded prompt/probe retries; <=0 means 3

	reader *bufio.Reader
}

// NewTerminalWizard returns a Wizard wired to the real terminal with no-echo
// token entry via golang.org/x/term. probe is the connectivity check to run
// after the inputs are gathered.
func NewTerminalWizard(probe ProbeFunc) *Wizard {
	return &Wizard{In: os.Stdin, Out: os.Stdout, Probe: probe, MaxRetries: 3}
}

func (w *Wizard) maxRetries() int {
	if w.MaxRetries <= 0 {
		return 3
	}
	return w.MaxRetries
}

func (w *Wizard) out() io.Writer {
	if w.Out == nil {
		return os.Stdout
	}
	return w.Out
}

func (w *Wizard) br() *bufio.Reader {
	if w.reader == nil {
		in := w.In
		if in == nil {
			in = os.Stdin
		}
		w.reader = bufio.NewReader(in)
	}
	return w.reader
}

// readLine reads one line, trimming the trailing newline. A final line without a
// trailing newline is still returned; a true EOF with no data returns the error
// so callers (and the non-TTY guard in main) never spin.
func (w *Wizard) readLine() (string, error) {
	line, err := w.br().ReadString('\n')
	if err != nil && len(line) == 0 {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// readSecret reads a line without echoing it. With ReadSecret set (tests) it is
// used verbatim; otherwise the terminal is put in no-echo mode via x/term.
func (w *Wizard) readSecret() (string, error) {
	if w.ReadSecret != nil {
		return w.ReadSecret()
	}
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	// ReadPassword consumes the Enter without echoing a newline; emit one so the
	// next prompt starts on its own line.
	fmt.Fprintln(w.out())
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Menu prints the two-option first-run menu and returns the chosen path. Junk
// input re-prompts up to MaxRetries before giving up.
func (w *Wizard) Menu() (Choice, error) {
	fmt.Fprintln(w.out(), "Welcome to Unravel.")
	fmt.Fprintln(w.out(), "  1) Connect to my Splunk")
	fmt.Fprintln(w.out(), "  2) Try the demo (no setup needed)")
	for attempt := 0; attempt < w.maxRetries(); attempt++ {
		fmt.Fprint(w.out(), "Choose [1/2]: ")
		line, err := w.readLine()
		if err != nil {
			return 0, err
		}
		switch strings.TrimSpace(strings.ToLower(line)) {
		case "1", "connect", "live":
			return ChoiceLive, nil
		case "2", "demo", "replay":
			return ChoiceDemo, nil
		}
		fmt.Fprintln(w.out(), "Please enter 1 or 2.")
	}
	return 0, fmt.Errorf("no valid menu choice after %d attempts", w.maxRetries())
}

// Run collects the Splunk connection (URL, masked token, self-signed yes/no),
// probes connectivity, and returns the validated Config. On a failed probe it
// re-collects and retries up to MaxRetries. It does not persist anything; the
// caller saves the returned Config.
func (w *Wizard) Run() (*Config, error) {
	var lastErr error
	for attempt := 1; attempt <= w.maxRetries(); attempt++ {
		c, err := w.collect()
		if err != nil {
			return nil, err
		}
		fmt.Fprintln(w.out(), "Checking connectivity to Splunk...")
		if perr := w.runProbe(c); perr != nil {
			lastErr = perr
			fmt.Fprintf(w.out(), "Could not connect: %v\n", perr)
			if attempt < w.maxRetries() {
				fmt.Fprintln(w.out(), "Let's try those details again.")
			}
			continue
		}
		fmt.Fprintln(w.out(), "Connected to Splunk.")
		return c, nil
	}
	return nil, fmt.Errorf("could not establish a Splunk connection after %d attempts: %w", w.maxRetries(), lastErr)
}

func (w *Wizard) runProbe(c *Config) error {
	if w.Probe == nil {
		return nil
	}
	return w.Probe(c.SplunkURL, c.SplunkToken, c.SplunkInsecure)
}

// collect gathers one full set of connection inputs.
func (w *Wizard) collect() (*Config, error) {
	splunkURL, err := w.promptURL()
	if err != nil {
		return nil, err
	}
	token, err := w.promptToken()
	if err != nil {
		return nil, err
	}
	insecure, err := w.promptYesNo("Is the Splunk certificate self-signed (skip TLS verification)?", false)
	if err != nil {
		return nil, err
	}
	return &Config{SplunkURL: splunkURL, SplunkToken: token, SplunkInsecure: insecure}, nil
}

// promptURL reads the Splunk REST URL, defaulting on empty input and validating
// that it parses with an http(s) scheme and a host.
func (w *Wizard) promptURL() (string, error) {
	for attempt := 0; attempt < w.maxRetries(); attempt++ {
		fmt.Fprintf(w.out(), "Splunk REST URL [%s]: ", defaultSplunkURL)
		line, err := w.readLine()
		if err != nil {
			return "", err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return defaultSplunkURL, nil
		}
		if err := validateSplunkURL(line); err != nil {
			fmt.Fprintf(w.out(), "That does not look like a valid URL: %v\n", err)
			continue
		}
		return line, nil
	}
	return "", fmt.Errorf("no valid Splunk URL after %d attempts", w.maxRetries())
}

// promptToken reads the bearer token without echo and rejects an empty value.
func (w *Wizard) promptToken() (string, error) {
	for attempt := 0; attempt < w.maxRetries(); attempt++ {
		fmt.Fprint(w.out(), "Splunk bearer token: ")
		token, err := w.readSecret()
		if err != nil {
			return "", err
		}
		token = strings.TrimSpace(token)
		if token != "" {
			return token, nil
		}
		fmt.Fprintln(w.out(), "The token cannot be empty.")
	}
	return "", fmt.Errorf("no token provided after %d attempts", w.maxRetries())
}

// promptYesNo reads a yes/no answer with the given default applied on empty input.
func (w *Wizard) promptYesNo(question string, def bool) (bool, error) {
	hint := "[y/N]"
	if def {
		hint = "[Y/n]"
	}
	for attempt := 0; attempt < w.maxRetries(); attempt++ {
		fmt.Fprintf(w.out(), "%s %s: ", question, hint)
		line, err := w.readLine()
		if err != nil {
			return false, err
		}
		switch strings.TrimSpace(strings.ToLower(line)) {
		case "":
			return def, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
		fmt.Fprintln(w.out(), "Please answer y or n.")
	}
	return false, fmt.Errorf("no valid yes/no answer after %d attempts", w.maxRetries())
}

// validateSplunkURL checks that s is an absolute http(s) URL with a host.
func validateSplunkURL(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("URL must start with http:// or https://")
	}
	if u.Host == "" {
		return fmt.Errorf("URL must include a host")
	}
	return nil
}
