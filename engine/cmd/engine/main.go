// Command engine is the streaming Causal Reconstruction Engine binary. It
// boots the configured source (live Splunk export or replay from testdata),
// wires the in-memory graph, scorer, chain extractor, and AI narrator into the
// pipeline, and exposes the resulting events to UI clients over WebSocket.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	engineroot "github.com/luigifernandez/unravel/engine"
	"github.com/luigifernandez/unravel/engine/internal/ai"
	"github.com/luigifernandez/unravel/engine/internal/api"
	"github.com/luigifernandez/unravel/engine/internal/graph"
	"github.com/luigifernandez/unravel/engine/internal/intel"
	"github.com/luigifernandez/unravel/engine/internal/pipeline"
	"github.com/luigifernandez/unravel/engine/internal/scorer"
	"github.com/luigifernandez/unravel/engine/internal/setup"
	"github.com/luigifernandez/unravel/engine/internal/splunk"
	"golang.org/x/term"
)

// embeddedGeminiKey is an optional Gemini API key compiled into the binary at
// build time via -ldflags "-X main.embeddedGeminiKey=<key>" (sourced from a
// gitignored secret file, never committed). It is empty in a plain `go build`,
// in which case the engine falls back to the stub narrator. Runtime precedence
// is --gemini-key flag > GEMINI_API_KEY env > this embedded key > stub. A key
// baked into a distributed binary is extractable from it, so this is a
// controlled-distribution convenience, not a production secret-management pattern.
var embeddedGeminiKey string

type config struct {
	mode           string
	bind           string
	port           int
	open           bool
	apiToken       string
	replaySpeed    float64
	testdataDir    string
	splunkURL      string
	splunkToken    string
	splunkQuery    string
	splunkEarliest string
	splunkLatest   string
	splunkMCPURL   string
	splunkMCPToken string
	splunkInsecure bool
	splunkCACert   string
	threshold      float64
	maxNodes       int
	apiKey         string
	nvdKey         string
	hecURL         string
	hecToken       string
	hecIndex       string
	hecSourcetype  string

	// Incident-scoping flags (the incident-triggered-pivot story). earliest and
	// latest are the canonical time bounds; --splunk-earliest/--splunk-latest
	// remain accepted aliases reconciled in parseFlags. incidentWindow scopes a
	// run to a trailing time window; incidentIdle auto-finalizes the incident
	// after the stream goes quiet; retention age-bounds the live graph; hostMap
	// canonicalizes host aliases onto one node.
	earliest       string
	latest         string
	incidentWindow time.Duration
	incidentIdle   time.Duration
	retention      time.Duration
	hostMap        string
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	// `unravel setup` forces the interactive wizard regardless of any saved
	// config. It is handled before flag parsing because the flag package has no
	// subcommand support and would mishandle a leading non-flag argument.
	if isSetupSubcommand(os.Args[1:]) {
		os.Exit(runSetup(logger))
	}

	cfg, set := parseFlags()
	resolveGeminiKey(&cfg)

	// A bare `unravel` (no flags) is the setup-wizard front door. Any explicit
	// flag (including --mode=...) keeps the original behavior byte-for-byte:
	// no config load, no prompt, no auto-browser.
	openBrowser := false
	if len(set) == 0 {
		var err error
		cfg, openBrowser, err = resolveBareInvocation(cfg, logger)
		if err != nil {
			logger.Error("setup failed", "err", err)
			os.Exit(1)
		}
	}

	// --open opts an explicit-flag invocation (e.g. --mode=replay --open, used by
	// the Windows run.cmd) into the same browser auto-open a bare `unravel` does.
	if cfg.open {
		openBrowser = true
	}

	if openBrowser {
		go openBrowserWhenReady(cfg)
	}

	if err := run(cfg, logger); err != nil {
		logger.Error("engine exited with error", "err", err)
		os.Exit(1)
	}
}

// isSetupSubcommand reports whether the args invoke the `setup` subcommand.
func isSetupSubcommand(args []string) bool {
	return len(args) > 0 && args[0] == "setup"
}

// resolveGeminiKey applies the build-time embedded Gemini key as the lowest-
// priority fallback. cfg.apiKey already holds the --gemini-key flag value or the
// GEMINI_API_KEY env default after parseFlags, so this only fills a still-empty
// key, yielding precedence flag > env > embedded > "" (stub).
func resolveGeminiKey(cfg *config) {
	if cfg.apiKey == "" {
		cfg.apiKey = embeddedGeminiKey
	}
}

// resolveBareInvocation handles a flagless `unravel`. With a saved config it
// goes straight to live mode; otherwise it runs the first-run menu and, for the
// connect path, the Splunk wizard. It returns the resolved config and whether to
// auto-open the browser (true for interactive launches). The demo path persists
// nothing. Explicit-flag invocations never reach here.
func resolveBareInvocation(cfg config, logger *slog.Logger) (config, bool, error) {
	path, err := setup.ConfigPath()
	if err != nil {
		return cfg, false, err
	}
	saved, err := setup.Load(path)
	if errors.Is(err, setup.ErrCorruptConfig) {
		logger.Warn("saved config is unreadable; re-running setup", "path", path, "err", err)
		saved = nil
	} else if err != nil {
		return cfg, false, err
	}

	if saved != nil {
		applySetupConfig(&cfg, saved)
		cfg.mode = "live"
		logger.Info("loaded saved Splunk connection", "path", path, "url", saved.SplunkURL)
		return cfg, true, nil
	}

	// First run (or recovered-from-corrupt): an interactive terminal is required.
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		printNonInteractiveUsage()
		os.Exit(2)
	}

	wiz := setup.NewTerminalWizard(makeProbe())
	choice, err := wiz.Menu()
	if err != nil {
		return cfg, false, fmt.Errorf("read menu choice: %w", err)
	}
	if choice == setup.ChoiceDemo {
		cfg.mode = "replay" // persist nothing; demo is stateless
		return cfg, true, nil
	}

	collected, err := wiz.Run()
	if err != nil {
		return cfg, false, err
	}
	if err := setup.Save(path, collected); err != nil {
		return cfg, false, fmt.Errorf("save config: %w", err)
	}
	logger.Info("saved Splunk connection", "path", path)
	applySetupConfig(&cfg, collected)
	cfg.mode = "live"
	return cfg, true, nil
}

// runSetup drives `unravel setup`: it reconfigures the Splunk connection
// directly (no menu), saves it, and launches live mode with the browser. It
// returns the process exit code.
func runSetup(logger *slog.Logger) int {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		printNonInteractiveUsage()
		return 2
	}
	path, err := setup.ConfigPath()
	if err != nil {
		logger.Error("setup failed", "err", err)
		return 1
	}
	collected, err := setup.NewTerminalWizard(makeProbe()).Run()
	if err != nil {
		logger.Error("setup failed", "err", err)
		return 1
	}
	if err := setup.Save(path, collected); err != nil {
		logger.Error("setup failed", "err", err)
		return 1
	}
	logger.Info("saved Splunk connection", "path", path)

	// Build a config with engine defaults (flag.Parse stops at the leading
	// "setup" arg, so every flag keeps its default), then overlay the connection.
	cfg, _ := parseFlags()
	resolveGeminiKey(&cfg)
	applySetupConfig(&cfg, collected)
	cfg.mode = "live"

	go openBrowserWhenReady(cfg)
	if err := run(cfg, logger); err != nil {
		logger.Error("engine exited with error", "err", err)
		return 1
	}
	return 0
}

// makeProbe adapts the engine's startup connectivity check into the wizard's
// ProbeFunc so the wizard validates a connection exactly as live mode will.
func makeProbe() setup.ProbeFunc {
	return func(splunkURL, token string, insecure bool) error {
		c := config{splunkURL: splunkURL, splunkToken: token, splunkInsecure: insecure}
		tlsCfg, err := loadSplunkTLS(c) // no --splunk-ca-cert here -> (nil, nil)
		if err != nil {
			return err
		}
		return checkSplunk(c, tlsCfg)
	}
}

// applySetupConfig overlays a saved/collected Splunk connection onto cfg. Only
// the three wizard-owned fields are touched; everything else stays at its flag
// default so the rest of run() behaves identically to a live invocation.
func applySetupConfig(cfg *config, s *setup.Config) {
	cfg.splunkURL = s.SplunkURL
	cfg.splunkToken = s.SplunkToken
	cfg.splunkInsecure = s.SplunkInsecure
}

// printNonInteractiveUsage explains how to run without a terminal (CI/pipes),
// where the interactive wizard cannot prompt.
func printNonInteractiveUsage() {
	fmt.Fprintln(os.Stderr, "No saved configuration and stdin is not a terminal.")
	fmt.Fprintln(os.Stderr, "Run 'unravel setup' in a terminal, or pass flags, for example:")
	fmt.Fprintln(os.Stderr, "  unravel --mode=replay")
	fmt.Fprintln(os.Stderr, "  unravel --mode=live --splunk-url=https://splunk:8089 --splunk-token=<token>")
}

// browserHost maps a bind address to a host a browser can actually reach: a
// wildcard bind (0.0.0.0 / ::) becomes loopback, and IPv6 literals are bracketed
// for use in a URL and a dial address.
func browserHost(bind string) string {
	switch bind {
	case "", "0.0.0.0":
		return "127.0.0.1"
	case "::", "[::]":
		return "[::1]"
	}
	if ip := net.ParseIP(bind); ip != nil && ip.To4() == nil {
		return "[" + bind + "]"
	}
	return bind
}

// openBrowserWhenReady waits for the HTTP server to accept connections, prints
// the local URL, and best-effort opens it in the default browser. Opening is
// non-fatal; the URL is always printed.
func openBrowserWhenReady(cfg config) {
	host := browserHost(cfg.bind)
	addr := fmt.Sprintf("%s:%d", host, cfg.port)
	waitForListen(addr, 5*time.Second)
	url := fmt.Sprintf("http://%s:%d", host, cfg.port)
	fmt.Fprintf(os.Stdout, "Open %s in your browser\n", url)
	_ = setup.Open(url)
}

// waitForListen polls addr until a TCP connection succeeds or the timeout
// elapses. It returns whether the listener became reachable.
func waitForListen(addr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func parseFlags() (config, map[string]bool) {
	var cfg config
	var deprecatedInsecure bool
	flag.StringVar(&cfg.mode, "mode", "replay", "engine mode: live | replay | ai-off")
	flag.StringVar(&cfg.bind, "bind", "127.0.0.1", "HTTP/WebSocket listen address")
	flag.IntVar(&cfg.port, "port", 8080, "HTTP/WebSocket listen port")
	flag.BoolVar(&cfg.open, "open", false, "open the demo in the default browser once the server is listening")
	flag.StringVar(&cfg.apiToken, "api-token", os.Getenv("SPLUNK_UNRAVEL_API_TOKEN"), "shared bearer token required on the HTTP/WebSocket API (env SPLUNK_UNRAVEL_API_TOKEN; empty disables auth)")
	flag.Float64Var(&cfg.replaySpeed, "replay-speed", 1.0, "timeline playback multiplier (replay mode)")
	flag.StringVar(&cfg.testdataDir, "testdata", "testdata", "directory holding replay timelines")
	flag.StringVar(&cfg.splunkURL, "splunk-url", "https://localhost:8089", "Splunk REST base URL (live mode)")
	flag.StringVar(&cfg.splunkToken, "splunk-token", "", "Splunk bearer token (live mode; env SPLUNK_TOKEN)")
	flag.StringVar(&cfg.splunkQuery, "splunk-search", "search index=sysmon", "Splunk search expression (live mode)")
	flag.StringVar(&cfg.splunkEarliest, "splunk-earliest", "rt", "alias for --earliest (Splunk earliest_time bound, e.g. rt, -15m, or an absolute time)")
	flag.StringVar(&cfg.splunkLatest, "splunk-latest", "", "alias for --latest (Splunk latest_time bound; empty means open-ended)")
	flag.StringVar(&cfg.earliest, "earliest", "", "earliest_time bound for the incident window (e.g. rt, -15m, 2026-06-14T00:00:00Z); in replay, scopes the timeline; empty inherits --splunk-earliest")
	flag.StringVar(&cfg.latest, "latest", "", "latest_time bound for the incident window (empty means open-ended); in replay, scopes the timeline; empty inherits --splunk-latest")
	flag.DurationVar(&cfg.incidentWindow, "incident-window", 0, "scope the run to the trailing time window of activity, e.g. 30m (replay: last 30m of the timeline; live with no --earliest: earliest_time=-30m); 0 disables")
	flag.DurationVar(&cfg.incidentIdle, "incident-idle", 0, "auto-finalize the incident and shut down cleanly after no new events for this long, e.g. 2m; 0 disables")
	flag.DurationVar(&cfg.retention, "retention", 0, "evict graph nodes whose newest event is older than this age, swept periodically, e.g. 1h; 0 means unbounded")
	flag.StringVar(&cfg.hostMap, "host-map", "", "comma-separated host alias=canonical pairs to collapse onto one node, e.g. \"dc01=DC01.corp.local,10.0.0.5=DC01.corp.local\"")
	flag.StringVar(&cfg.splunkMCPURL, "splunk-mcp-url", "", "Splunk MCP Server endpoint URL; when set in live mode, narrator enrichment runs through the MCP server instead of REST")
	flag.StringVar(&cfg.splunkMCPToken, "splunk-mcp-token", "", "Splunk MCP Server bearer token (required when --splunk-mcp-url is set; env SPLUNK_MCP_TOKEN)")
	flag.BoolVar(&cfg.splunkInsecure, "splunk-insecure", false, "skip TLS verification for the Splunk REST/HEC/MCP endpoints (does NOT affect public NVD/CISA fetches)")
	flag.BoolVar(&deprecatedInsecure, "insecure", false, "DEPRECATED alias for --splunk-insecure")
	flag.StringVar(&cfg.splunkCACert, "splunk-ca-cert", "", "path to a PEM CA bundle to trust for the Splunk REST/HEC/MCP endpoints (corporate private CAs)")
	flag.Float64Var(&cfg.threshold, "threshold", 0.5, "scorer trigger threshold")
	flag.IntVar(&cfg.maxNodes, "max-nodes", 0, "cap the live provenance graph at N nodes, evicting the least-recently-touched (0 means unbounded)")
	flag.StringVar(&cfg.apiKey, "gemini-key", os.Getenv("GEMINI_API_KEY"), "Google Gemini API key (omit to fall back to stub narrator)")
	flag.StringVar(&cfg.nvdKey, "nvd-key", os.Getenv("NVD_API_KEY"), "NVD API key to lift the CVE rate limit (live mode, optional)")
	flag.StringVar(&cfg.hecURL, "hec-url", "", "Splunk HEC base URL for chain result write-back, e.g. https://splunk:8088 (disabled when empty)")
	flag.StringVar(&cfg.hecToken, "hec-token", "", "Splunk HEC token (required when --hec-url is set; env SPLUNK_HEC_TOKEN)")
	flag.StringVar(&cfg.hecIndex, "hec-index", "", "Splunk index for HEC write-back (uses token default when empty)")
	flag.StringVar(&cfg.hecSourcetype, "hec-sourcetype", "causal_chain_result", "Splunk sourcetype for HEC write-back")
	flag.Parse()

	// Capture which flags the operator explicitly set. An empty set means a bare
	// `unravel` invocation, which routes to the setup wizard.
	set := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { set[f.Name] = true })

	// --insecure stays a deprecated alias: either flag turns it on.
	if deprecatedInsecure {
		cfg.splunkInsecure = true
	}

	reconcileTimeBounds(&cfg, set)
	applySecretEnvFallbacks(&cfg)
	return cfg, set
}

// reconcileTimeBounds makes --earliest/--latest the canonical time bounds while
// keeping --splunk-earliest/--splunk-latest as accepted aliases. An explicitly
// set canonical flag always wins; otherwise the canonical value is seeded from
// the alias (so the live source, which reads cfg.splunkEarliest/Latest, still
// sees the right value) and vice versa, so both names end up holding the same
// resolved bound regardless of which the operator typed.
func reconcileTimeBounds(cfg *config, set map[string]bool) {
	switch {
	case set["earliest"]:
		// Canonical wins; mirror onto the alias so the live REST source honors it.
		cfg.splunkEarliest = cfg.earliest
	case set["splunk-earliest"]:
		cfg.earliest = cfg.splunkEarliest
	default:
		// Neither set: canonical inherits the alias default ("rt").
		cfg.earliest = cfg.splunkEarliest
	}

	switch {
	case set["latest"]:
		cfg.splunkLatest = cfg.latest
	case set["splunk-latest"]:
		cfg.latest = cfg.splunkLatest
	default:
		cfg.latest = cfg.splunkLatest
	}
}

// applySecretEnvFallbacks fills empty token fields from the environment so
// secrets need not be passed on the command line. An explicitly-set flag (a
// non-empty field) always wins over the env, mirroring the GEMINI_API_KEY /
// NVD_API_KEY pattern.
func applySecretEnvFallbacks(cfg *config) {
	if cfg.splunkToken == "" {
		cfg.splunkToken = os.Getenv("SPLUNK_TOKEN")
	}
	if cfg.hecToken == "" {
		cfg.hecToken = os.Getenv("SPLUNK_HEC_TOKEN")
	}
	if cfg.splunkMCPToken == "" {
		cfg.splunkMCPToken = os.Getenv("SPLUNK_MCP_TOKEN")
	}
}

func run(cfg config, logger *slog.Logger) error {
	tlsCfg, err := loadSplunkTLS(cfg)
	if err != nil {
		return fmt.Errorf("splunk tls: %w", err)
	}

	if cfg.mode == "live" {
		probeSplunk(cfg, tlsCfg, logger)
	}

	// Replay/ai-off read fixtures from --testdata on disk. When that directory is
	// absent (the installed `unravel` run from an arbitrary directory), fall back
	// to the fixtures embedded in the binary so the demo still runs. Resolving here
	// means both buildSource and buildNarrator below pick up the same directory.
	if cfg.mode == "replay" || cfg.mode == "ai-off" {
		resolved, cleanup, err := resolveReplayTestdata(cfg.testdataDir)
		if err != nil {
			return fmt.Errorf("replay fixtures: %w", err)
		}
		defer cleanup()
		if resolved != cfg.testdataDir {
			logger.Info("testdata directory not found; using replay fixtures embedded in the binary", "requested", cfg.testdataDir, "dir", resolved)
		}
		cfg.testdataDir = resolved
	}

	source, err := buildSource(cfg, tlsCfg)
	if err != nil {
		return fmt.Errorf("source: %w", err)
	}
	defer source.Close()

	narrator := buildNarrator(cfg, tlsCfg, logger)
	intelAgent := buildIntelAgent(cfg, logger)

	g := graph.New()
	sc := scorer.New(scorer.Config{
		Threshold: cfg.threshold,
		SensitiveLabels: []string{
			"lsass.exe", "ntdsutil.exe", "secretsdump.py",
		},
	})

	// Bound live memory growth when requested: evicting graph nodes also prunes
	// the scorer's per-node/per-edge state so the two stay consistent.
	if cfg.maxNodes > 0 || cfg.retention > 0 {
		g.SetEvictionCallback(func(nodeIDs, edgeIDs []string) {
			sc.PruneNodes(nodeIDs)
			sc.PruneEdges(edgeIDs)
		})
	}
	if cfg.maxNodes > 0 {
		g.SetMaxNodes(cfg.maxNodes)
		logger.Info("graph node-count bound enabled", "max_nodes", cfg.maxNodes)
	}
	if cfg.retention > 0 {
		logger.Info("graph age retention enabled", "retention", cfg.retention)
	}

	bcast := api.NewBroadcaster()
	defer bcast.Close()

	hec, err := buildHEC(cfg, tlsCfg, logger)
	if err != nil {
		return fmt.Errorf("hec: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hostMap := parseHostMap(cfg.hostMap)
	if len(hostMap) > 0 {
		logger.Info("host alias map enabled", "aliases", len(hostMap))
	}

	pcfg := pipeline.Config{
		Source:      source,
		Graph:       g,
		Scorer:      sc,
		Narrator:    narrator,
		IntelAgent:  intelAgent,
		Broadcaster: bcast,
		HEC:         hec,
		Logger:      logger,
		HostMap:     hostMap,
		IdleTimeout: cfg.incidentIdle,
	}
	if cfg.incidentIdle > 0 {
		logger.Info("incident idle auto-finalize enabled", "incident_idle", cfg.incidentIdle)
		pcfg.OnIdle = func() {
			logger.Info("incident idle timeout reached; finalizing and shutting down", "incident_idle", cfg.incidentIdle)
			cancel()
		}
	}
	p, err := pipeline.New(pcfg)
	if err != nil {
		return fmt.Errorf("pipeline: %w", err)
	}

	loopback := isLoopback(cfg.bind)
	if shouldWarnUnauthenticated(cfg.bind, cfg.apiToken) {
		logger.Warn("API is bound to a non-loopback address with NO --api-token; the WebSocket/HTTP API is unauthenticated and world-reachable",
			"bind", cfg.bind, "port", cfg.port)
	}
	server := api.NewServer(bcast, api.StaticFS(),
		api.WithAuthToken(cfg.apiToken),
		api.WithAllowEmptyOrigin(loopback),
	)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signals
		logger.Info("shutdown requested")
		cancel()
	}()

	if cfg.retention > 0 {
		go runRetentionSweep(ctx, g, cfg.retention, logger)
	}

	startSource(source, ctx)

	addr := fmt.Sprintf("%s:%d", cfg.bind, cfg.port)
	logger.Info("engine listening", "addr", addr, "mode", cfg.mode)

	errCh := make(chan error, 2)
	go func() { errCh <- server.ListenAndServe(ctx, addr) }()
	go func() { errCh <- p.Run(ctx) }()

	if err := <-errCh; err != nil {
		cancel()
		return err
	}
	cancel()
	return nil
}

func buildSource(cfg config, tlsCfg *tls.Config) (splunk.Source, error) {
	switch cfg.mode {
	case "replay", "ai-off":
		timelines, err := discoverTimelines(cfg.testdataDir)
		if err != nil {
			return nil, err
		}
		if len(timelines) == 0 {
			return nil, fmt.Errorf("no timeline files matched %s/*.json", cfg.testdataDir)
		}
		opts := []splunk.MockOption{splunk.WithReplaySpeed(cfg.replaySpeed)}
		// In replay, the time bounds scope the canned timeline so the demo can show
		// the incident-triggered pivot. "rt" / "now" are live-only Splunk tokens
		// with no fixed instant, so they do not bound a recorded timeline; only
		// absolute or clearly-relative bounds are applied.
		earliest, hasEarliest := replayBound(cfg.earliest)
		latest, hasLatest := replayBound(cfg.latest)
		if hasEarliest || hasLatest {
			opts = append(opts, splunk.WithTimeBounds(earliest, latest))
		}
		if cfg.incidentWindow > 0 {
			opts = append(opts, splunk.WithIncidentWindow(cfg.incidentWindow))
		}
		return splunk.NewMockFromFiles(timelines, opts...)
	case "live":
		if cfg.splunkToken == "" {
			return nil, fmt.Errorf("--splunk-token (or SPLUNK_TOKEN) is required in live mode")
		}
		earliest := cfg.earliest
		// --incident-window without an explicit earliest sets a relative bound so
		// the live export tails only the trailing window of activity.
		if cfg.incidentWindow > 0 && !timeBoundExplicit(cfg.earliest) {
			earliest = fmt.Sprintf("-%ds", int(cfg.incidentWindow.Seconds()))
		}
		return splunk.NewRESTSource(splunk.RESTConfig{
			BaseURL:   cfg.splunkURL,
			Token:     cfg.splunkToken,
			Search:    cfg.splunkQuery,
			Earliest:  earliest,
			Latest:    cfg.latest,
			Insecure:  cfg.splunkInsecure,
			TLSConfig: tlsCfg,
			Logger:    slog.Default(),
		}), nil
	default:
		return nil, fmt.Errorf("unknown --mode=%q (live | replay | ai-off)", cfg.mode)
	}
}

// timeBoundExplicit reports whether a time-bound string names a concrete bound
// (absolute or relative) rather than a live-only streaming token. "rt", "now",
// and "" are not concrete instants, so an --incident-window may supply one.
func timeBoundExplicit(s string) bool {
	s = strings.TrimSpace(strings.ToLower(s))
	switch s {
	case "", "rt", "now", "rt-0", "+0", "-0":
		return false
	}
	return true
}

// replayBound resolves a time-bound string to an absolute instant for scoping a
// recorded replay timeline. Absolute RFC3339 times and Splunk-style relative
// offsets ("-15m", "-2h", "-1d") are honored; live-only tokens (rt, now, empty)
// yield ok=false so they impose no bound on a canned timeline. Relative offsets
// are measured from wall-clock now, mirroring how Splunk evaluates them live.
func replayBound(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if !timeBoundExplicit(s) {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	if d, ok := parseSplunkRelative(s); ok {
		return time.Now().UTC().Add(d), true
	}
	// Unrecognized but explicit: do not guess. Impose no replay bound rather than
	// risk filtering the whole timeline out.
	return time.Time{}, false
}

// parseSplunkRelative parses a leading-signed Splunk relative time like "-15m",
// "-2h", or "-1d" into a Duration. Supported units: s, m, h, d. The "@" snap
// suffix Splunk allows is ignored (we drop everything from "@" on). Returns
// ok=false for anything it cannot parse.
func parseSplunkRelative(s string) (time.Duration, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if at := strings.IndexByte(s, '@'); at >= 0 {
		s = s[:at]
	}
	if s == "" {
		return 0, false
	}
	sign := time.Duration(1)
	switch s[0] {
	case '-':
		sign = -1
		s = s[1:]
	case '+':
		s = s[1:]
	}
	if s == "" {
		return 0, false
	}
	unit := s[len(s)-1]
	numStr := s[:len(s)-1]
	mult, ok := map[byte]time.Duration{
		's': time.Second,
		'm': time.Minute,
		'h': time.Hour,
		'd': 24 * time.Hour,
	}[unit]
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(numStr)
	if err != nil {
		return 0, false
	}
	return sign * time.Duration(n) * mult, true
}

// parseHostMap parses the --host-map "alias=canonical,alias2=canonical" string
// into a lowercase-keyed lookup table. Blank entries and entries missing "=" are
// skipped. Returns nil for an empty spec so the pipeline treats it as a no-op.
func parseHostMap(spec string) map[string]string {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil
	}
	out := map[string]string{}
	for _, pair := range strings.Split(spec, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		eq := strings.IndexByte(pair, '=')
		if eq <= 0 {
			continue
		}
		alias := strings.TrimSpace(pair[:eq])
		canon := strings.TrimSpace(pair[eq+1:])
		if alias == "" || canon == "" {
			continue
		}
		out[strings.ToLower(alias)] = canon
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// loadSplunkTLS reads the optional --splunk-ca-cert PEM bundle into a tls.Config
// RootCAs pool for the Splunk transports. Returns nil (use system roots) when no
// path is given.
func loadSplunkTLS(cfg config) (*tls.Config, error) {
	if cfg.splunkCACert == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(cfg.splunkCACert)
	if err != nil {
		return nil, fmt.Errorf("read ca cert %s: %w", cfg.splunkCACert, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates parsed from %s", cfg.splunkCACert)
	}
	return &tls.Config{RootCAs: pool}, nil
}

// checkSplunk performs a synchronous connectivity check against the Splunk REST
// API and returns an error describing any failure. The error text references the
// URL, status, and response body only, never the bearer token, so callers (the
// setup wizard) can safely surface it to the user. It is the single source of
// truth for "is this a good Splunk connection", shared by the startup probe and
// the wizard.
func checkSplunk(cfg config, tlsCfg *tls.Config) error {
	endpoint := strings.TrimRight(cfg.splunkURL, "/") + "/services/server/info?output_mode=json"
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsClientConfig(tlsCfg, cfg.splunkInsecure),
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("build probe request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.splunkToken)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", cfg.splunkURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("authentication rejected (status %d); check the token", resp.StatusCode)
	}
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// probeSplunk wraps checkSplunk for the startup path: a bad host/port/token logs
// a prominent warning and lets the engine continue (the reconnect loop keeps
// trying) instead of failing the process.
func probeSplunk(cfg config, tlsCfg *tls.Config, logger *slog.Logger) {
	if err := checkSplunk(cfg, tlsCfg); err != nil {
		logger.Warn("splunk connectivity probe failed; continuing (reconnect loop will retry)", "url", cfg.splunkURL, "err", err)
		return
	}
	logger.Info("splunk connectivity probe ok", "url", cfg.splunkURL)
}

// tlsClientConfig mirrors splunk.buildTLSConfig for the in-package probe so the
// startup check honors --splunk-ca-cert and --splunk-insecure identically.
func tlsClientConfig(base *tls.Config, insecure bool) *tls.Config {
	var c *tls.Config
	if base != nil {
		c = base.Clone()
	} else {
		c = &tls.Config{}
	}
	if insecure {
		c.InsecureSkipVerify = true //nolint:gosec
	}
	return c
}

// shouldWarnUnauthenticated reports whether the API is exposed on a
// non-loopback address with no bearer token, i.e. world-reachable and
// unauthenticated. A loopback bind or any non-empty token suppresses the
// warning.
func shouldWarnUnauthenticated(bind, apiToken string) bool {
	return !isLoopback(bind) && apiToken == ""
}

// isLoopback reports whether bind is a loopback address (so origin-less
// WebSocket upgrades and a missing API token are acceptable).
func isLoopback(bind string) bool {
	switch bind {
	case "", "127.0.0.1", "::1", "localhost":
		return true
	}
	if ip := net.ParseIP(bind); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func startSource(s splunk.Source, ctx context.Context) {
	switch ms := s.(type) {
	case *splunk.MockSource:
		ms.Start()
	case *splunk.RESTSource:
		ms.Start(ctx)
	}
}

// runRetentionSweep periodically evicts graph nodes whose newest event is older
// than the retention age. The sweep interval is a fraction of the retention
// window (capped to a sane range) so eviction is timely without busy-looping.
// It returns when ctx is canceled. The eviction callback registered in run()
// keeps the scorer's per-node/per-edge state in step with each sweep.
func runRetentionSweep(ctx context.Context, g *graph.Graph, retention time.Duration, logger *slog.Logger) {
	interval := retention / 4
	if interval < 15*time.Second {
		interval = 15 * time.Second
	}
	if interval > 5*time.Minute {
		interval = 5 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().UTC().Add(-retention)
			if n := g.PruneOlderThan(cutoff); n > 0 {
				logger.Info("graph retention sweep evicted aged nodes", "evicted", n, "older_than", retention)
			}
		}
	}
}

// buildHEC returns a nil HECSink (disabling write-back) when --hec-url is
// unset, so replay and ai-off modes work without any Splunk instance.
func buildHEC(cfg config, tlsCfg *tls.Config, logger *slog.Logger) (pipeline.HECSink, error) {
	if cfg.hecURL == "" {
		return nil, nil
	}
	client, err := splunk.NewHECClient(splunk.HECConfig{
		URL:        cfg.hecURL,
		Token:      cfg.hecToken,
		Index:      cfg.hecIndex,
		Sourcetype: cfg.hecSourcetype,
		Insecure:   cfg.splunkInsecure,
		TLSConfig:  tlsCfg,
		Logger:     logger,
	})
	if err != nil {
		return nil, err
	}
	logger.Info("HEC write-back enabled", "url", cfg.hecURL, "index", cfg.hecIndex, "sourcetype", cfg.hecSourcetype)
	return client, nil
}

// Both the live MCPSearcher and the replay MockSearcher generate SPL via the
// SPLGenerator seam; these bindings are what gate the narrator's
// splunk_nl_search tool. The MockSearcher binding is why the SAIA loop is also
// exercised (as an honestly-labeled replay fixture) in demo mode.
var (
	_ ai.SPLGenerator = (*splunk.MCPSearcher)(nil)
	_ ai.SPLGenerator = (*splunk.MockSearcher)(nil)
)

func buildNarrator(cfg config, tlsCfg *tls.Config, logger *slog.Logger) ai.Narrator {
	if cfg.mode == "ai-off" || cfg.apiKey == "" {
		if cfg.mode != "ai-off" {
			logger.Info("gemini key not set, falling back to stub narrator")
		}
		return ai.NewStub()
	}
	var searcher ai.SplunkSearcher
	var searcherName string
	// nlGenSource honestly labels the natural-language-to-SPL backend in the
	// activity feed: the live MCP path is the real Splunk AI Assistant (SAIA);
	// the replay path is a fixture-backed simulation and says so.
	var nlGenSource string
	switch cfg.mode {
	case "live":
		if cfg.splunkMCPURL != "" {
			searcher = splunk.NewMCPSearcher(cfg.splunkMCPURL, cfg.splunkMCPToken, cfg.splunkInsecure, tlsCfg, logger)
			searcherName = "Splunk MCP Server"
			nlGenSource = "Splunk MCP Server / SAIA"
			logger.Info("narrator enrichment via Splunk MCP Server", "mcp_url", cfg.splunkMCPURL)
		} else {
			searcher = splunk.NewRESTSearcher(cfg.splunkURL, cfg.splunkToken, cfg.splunkInsecure, tlsCfg)
			searcherName = "Splunk REST API"
			logger.Info("narrator enrichment enabled", "splunk_url", cfg.splunkURL)
		}
	default:
		// Replay/demo: the MockSearcher also implements ai.SPLGenerator, so the
		// narrator's natural-language Splunk search (the SAIA loop) is exercised on
		// stage. The labels make clear this is a replay fixture, not a live call.
		searcher = splunk.NewMockSearcher(cfg.testdataDir)
		searcherName = "Splunk MCP Server / SAIA (replay fixture)"
		nlGenSource = "Splunk MCP Server / SAIA (replay fixture)"
		logger.Info("narrator enrichment using mock fixtures", "testdata_dir", cfg.testdataDir)
	}
	// Wrap the live narrator so any model/API failure degrades to the stub
	// instead of leaving the incident with no narration. The demo (and a live
	// run) keeps a populated narration panel even when Gemini is unreachable.
	gem := ai.NewGemini(ai.GeminiConfig{APIKey: cfg.apiKey, Searcher: searcher, SearcherName: searcherName, NLGenerateSource: nlGenSource})
	return ai.NewFallback(gem, ai.NewStub())
}

// buildIntelAgent mirrors buildNarrator: ai-off or a missing API key yields the
// deterministic snapshot-only agent (no LLM, no network), so both new tabs work
// with zero keys. With a key, the Gemini agent uses the live KEV/NVD source in
// BOTH live and replay mode: the CISA KEV catalog is a keyless public fetch and
// NVD is Splunk-independent, so the replay demo can truthfully show the agent
// reaching out to an external threat database and cross-referencing the chain.
// The source fails gracefully (tool results carry an error), so an offline
// demo still completes - the activity feed just reports the source unavailable.
func buildIntelAgent(cfg config, logger *slog.Logger) ai.ThreatIntelAgent {
	if cfg.mode == "ai-off" || cfg.apiKey == "" {
		logger.Info("threat-intel agent using deterministic ATT&CK snapshot")
		return ai.NewDeterministicIntel()
	}
	source := intel.NewRESTSource(intel.RESTConfig{NVDKey: cfg.nvdKey})
	logger.Info("threat-intel agent enrichment using live KEV/NVD", "mode", cfg.mode)
	return ai.NewGeminiIntel(ai.GeminiIntelConfig{APIKey: cfg.apiKey, Source: source})
}

// resolveReplayTestdata ensures replay/ai-off modes have their fixtures on disk.
// When dir actually contains a timeline (the normal case when run from the engine
// source tree, or any explicit --testdata path), it is used as-is and cleanup is a
// no-op. Otherwise the fixtures embedded in the binary are materialized into a
// fresh temp directory so the installed `unravel` runs its demo from ANY working
// directory. The returned cleanup removes that temp directory.
func resolveReplayTestdata(dir string) (string, func(), error) {
	noop := func() {}
	if timelines, err := discoverTimelines(dir); err == nil && len(timelines) > 0 {
		return dir, noop, nil
	}
	tmp, err := os.MkdirTemp("", "unravel-replay-")
	if err != nil {
		return "", noop, fmt.Errorf("create temp testdata: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }
	if err := extractReplayFS(tmp); err != nil {
		cleanup()
		return "", noop, fmt.Errorf("materialize embedded fixtures: %w", err)
	}
	return tmp, cleanup, nil
}

// extractReplayFS writes every fixture embedded in engineroot.ReplayFS under
// root, preserving the layout the replay loaders expect: the timeline at the top
// level and the enrichment fixtures under root/enrichment/. The leading
// "testdata/" embed prefix is stripped so the files land directly under root.
func extractReplayFS(root string) error {
	return fs.WalkDir(engineroot.ReplayFS, "testdata", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(p, "testdata"), "/")
		target := filepath.Join(root, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := engineroot.ReplayFS.ReadFile(p)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
}

// discoverTimelines returns every root-level chain-*.json file in dir (the
// replay timeline format). It deliberately skips subdirectories, so non-timeline
// fixtures parked under e.g. testdata/ws/ are never picked up as replay input.
func discoverTimelines(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if !strings.HasPrefix(e.Name(), "chain-") {
			continue
		}
		out = append(out, filepath.Join(dir, e.Name()))
	}
	return out, nil
}
