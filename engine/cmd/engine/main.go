// Command engine is the streaming Causal Reconstruction Engine binary. It
// boots the configured source (live Splunk export or replay from testdata),
// wires the in-memory graph, scorer, chain extractor, and AI narrator into the
// pipeline, and exposes the resulting events to UI clients over WebSocket.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/luigifernandez/unravel/engine/internal/ai"
	"github.com/luigifernandez/unravel/engine/internal/api"
	"github.com/luigifernandez/unravel/engine/internal/graph"
	"github.com/luigifernandez/unravel/engine/internal/intel"
	"github.com/luigifernandez/unravel/engine/internal/pipeline"
	"github.com/luigifernandez/unravel/engine/internal/scorer"
	"github.com/luigifernandez/unravel/engine/internal/splunk"
)

type config struct {
	mode           string
	bind           string
	port           int
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
}

func main() {
	cfg := parseFlags()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if err := run(cfg, logger); err != nil {
		logger.Error("engine exited with error", "err", err)
		os.Exit(1)
	}
}

func parseFlags() config {
	var cfg config
	var deprecatedInsecure bool
	flag.StringVar(&cfg.mode, "mode", "replay", "engine mode: live | replay | ai-off")
	flag.StringVar(&cfg.bind, "bind", "127.0.0.1", "HTTP/WebSocket listen address")
	flag.IntVar(&cfg.port, "port", 8080, "HTTP/WebSocket listen port")
	flag.StringVar(&cfg.apiToken, "api-token", os.Getenv("SPLUNK_UNRAVEL_API_TOKEN"), "shared bearer token required on the HTTP/WebSocket API (env SPLUNK_UNRAVEL_API_TOKEN; empty disables auth)")
	flag.Float64Var(&cfg.replaySpeed, "replay-speed", 1.0, "timeline playback multiplier (replay mode)")
	flag.StringVar(&cfg.testdataDir, "testdata", "testdata", "directory holding replay timelines")
	flag.StringVar(&cfg.splunkURL, "splunk-url", "https://localhost:8089", "Splunk REST base URL (live mode)")
	flag.StringVar(&cfg.splunkToken, "splunk-token", "", "Splunk bearer token (live mode; env SPLUNK_TOKEN)")
	flag.StringVar(&cfg.splunkQuery, "splunk-search", "search index=sysmon", "Splunk search expression (live mode)")
	flag.StringVar(&cfg.splunkEarliest, "splunk-earliest", "rt", "Splunk earliest_time bound for the live export (e.g. rt, -15m, or an absolute time); empty replays all history")
	flag.StringVar(&cfg.splunkLatest, "splunk-latest", "", "Splunk latest_time bound for the live export (empty means open-ended)")
	flag.StringVar(&cfg.splunkMCPURL, "splunk-mcp-url", "", "Splunk MCP Server endpoint URL; when set in live mode, narrator enrichment runs through the MCP server instead of REST")
	flag.StringVar(&cfg.splunkMCPToken, "splunk-mcp-token", "", "Splunk MCP Server bearer token (required when --splunk-mcp-url is set; env SPLUNK_MCP_TOKEN)")
	flag.BoolVar(&cfg.splunkInsecure, "splunk-insecure", false, "skip TLS verification for the Splunk REST/HEC/MCP endpoints (does NOT affect public NVD/CISA fetches)")
	flag.BoolVar(&deprecatedInsecure, "insecure", false, "DEPRECATED alias for --splunk-insecure")
	flag.StringVar(&cfg.splunkCACert, "splunk-ca-cert", "", "path to a PEM CA bundle to trust for the Splunk REST/HEC/MCP endpoints (corporate private CAs)")
	flag.Float64Var(&cfg.threshold, "threshold", 0.5, "scorer trigger threshold")
	flag.IntVar(&cfg.maxNodes, "max-nodes", 0, "cap the live provenance graph at N nodes, evicting the least-recently-touched (0 means unbounded)")
	flag.StringVar(&cfg.apiKey, "anthropic-key", os.Getenv("ANTHROPIC_API_KEY"), "Anthropic API key (omit to fall back to stub narrator)")
	flag.StringVar(&cfg.nvdKey, "nvd-key", os.Getenv("NVD_API_KEY"), "NVD API key to lift the CVE rate limit (live mode, optional)")
	flag.StringVar(&cfg.hecURL, "hec-url", "", "Splunk HEC base URL for chain result write-back, e.g. https://splunk:8088 (disabled when empty)")
	flag.StringVar(&cfg.hecToken, "hec-token", "", "Splunk HEC token (required when --hec-url is set; env SPLUNK_HEC_TOKEN)")
	flag.StringVar(&cfg.hecIndex, "hec-index", "", "Splunk index for HEC write-back (uses token default when empty)")
	flag.StringVar(&cfg.hecSourcetype, "hec-sourcetype", "causal_chain_result", "Splunk sourcetype for HEC write-back")
	flag.Parse()

	// --insecure stays a deprecated alias: either flag turns it on.
	if deprecatedInsecure {
		cfg.splunkInsecure = true
	}

	applySecretEnvFallbacks(&cfg)
	return cfg
}

// applySecretEnvFallbacks fills empty token fields from the environment so
// secrets need not be passed on the command line. An explicitly-set flag (a
// non-empty field) always wins over the env, mirroring the ANTHROPIC_API_KEY /
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
	if cfg.maxNodes > 0 {
		g.SetEvictionCallback(func(nodeIDs, edgeIDs []string) {
			sc.PruneNodes(nodeIDs)
			sc.PruneEdges(edgeIDs)
		})
		g.SetMaxNodes(cfg.maxNodes)
		logger.Info("graph retention bound enabled", "max_nodes", cfg.maxNodes)
	}

	bcast := api.NewBroadcaster()
	defer bcast.Close()

	hec, err := buildHEC(cfg, tlsCfg, logger)
	if err != nil {
		return fmt.Errorf("hec: %w", err)
	}

	p, err := pipeline.New(pipeline.Config{
		Source:      source,
		Graph:       g,
		Scorer:      sc,
		Narrator:    narrator,
		IntelAgent:  intelAgent,
		Broadcaster: bcast,
		HEC:         hec,
		Logger:      logger,
	})
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signals
		logger.Info("shutdown requested")
		cancel()
	}()

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
		return splunk.NewMockFromFiles(timelines, splunk.WithReplaySpeed(cfg.replaySpeed))
	case "live":
		if cfg.splunkToken == "" {
			return nil, fmt.Errorf("--splunk-token (or SPLUNK_TOKEN) is required in live mode")
		}
		return splunk.NewRESTSource(splunk.RESTConfig{
			BaseURL:   cfg.splunkURL,
			Token:     cfg.splunkToken,
			Search:    cfg.splunkQuery,
			Earliest:  cfg.splunkEarliest,
			Latest:    cfg.splunkLatest,
			Insecure:  cfg.splunkInsecure,
			TLSConfig: tlsCfg,
			Logger:    slog.Default(),
		}), nil
	default:
		return nil, fmt.Errorf("unknown --mode=%q (live | replay | ai-off)", cfg.mode)
	}
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

// probeSplunk performs a synchronous connectivity check against the Splunk REST
// API so a bad host/port/token fails loudly at startup instead of silently
// ingesting nothing. Non-fatal: it logs a prominent warning and lets the engine
// continue (the reconnect loop will keep trying).
func probeSplunk(cfg config, tlsCfg *tls.Config, logger *slog.Logger) {
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
		logger.Warn("splunk connectivity probe could not be built", "err", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+cfg.splunkToken)
	resp, err := client.Do(req)
	if err != nil {
		logger.Warn("splunk connectivity probe failed; check --splunk-url and network reachability", "url", cfg.splunkURL, "err", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		logger.Warn("splunk connectivity probe was rejected; check --splunk-token", "status", resp.StatusCode)
		return
	}
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		logger.Warn("splunk connectivity probe returned non-2xx", "status", resp.StatusCode, "body", strings.TrimSpace(string(body)))
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

// MCPSearcher is the only SplunkSearcher that also generates SPL via the Splunk
// AI Assistant; this binding is what gates the narrator's splunk_nl_search tool.
var _ ai.SPLGenerator = (*splunk.MCPSearcher)(nil)

func buildNarrator(cfg config, tlsCfg *tls.Config, logger *slog.Logger) ai.Narrator {
	if cfg.mode == "ai-off" || cfg.apiKey == "" {
		if cfg.mode != "ai-off" {
			logger.Info("anthropic key not set, falling back to stub narrator")
		}
		return ai.NewStub()
	}
	var searcher ai.SplunkSearcher
	var searcherName string
	switch cfg.mode {
	case "live":
		if cfg.splunkMCPURL != "" {
			searcher = splunk.NewMCPSearcher(cfg.splunkMCPURL, cfg.splunkMCPToken, cfg.splunkInsecure, tlsCfg, logger)
			searcherName = "Splunk MCP Server"
			logger.Info("narrator enrichment via Splunk MCP Server", "mcp_url", cfg.splunkMCPURL)
		} else {
			searcher = splunk.NewRESTSearcher(cfg.splunkURL, cfg.splunkToken, cfg.splunkInsecure, tlsCfg)
			searcherName = "Splunk REST API"
			logger.Info("narrator enrichment enabled", "splunk_url", cfg.splunkURL)
		}
	default:
		searcher = splunk.NewMockSearcher(cfg.testdataDir)
		searcherName = "Splunk (replay fixtures)"
		logger.Info("narrator enrichment using mock fixtures", "testdata_dir", cfg.testdataDir)
	}
	return ai.NewClaude(ai.ClaudeConfig{APIKey: cfg.apiKey, Searcher: searcher, SearcherName: searcherName})
}

// buildIntelAgent mirrors buildNarrator: ai-off or a missing API key yields the
// deterministic snapshot-only agent (no LLM, no network), so both new tabs work
// with zero keys. With a key, the Claude agent uses the live KEV/NVD source in
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
	return ai.NewClaudeIntel(ai.ClaudeIntelConfig{APIKey: cfg.apiKey, Source: source})
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
