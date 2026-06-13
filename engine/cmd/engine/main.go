// Command engine is the streaming Causal Reconstruction Engine binary. It
// boots the configured source (live Splunk export or replay from testdata),
// wires the in-memory graph, scorer, chain extractor, and AI narrator into the
// pipeline, and exposes the resulting events to UI clients over WebSocket.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

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
	replaySpeed    float64
	testdataDir    string
	splunkURL      string
	splunkToken    string
	splunkQuery    string
	splunkMCPURL   string
	splunkMCPToken string
	insecure       bool
	threshold      float64
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
	flag.StringVar(&cfg.mode, "mode", "replay", "engine mode: live | replay | ai-off")
	flag.StringVar(&cfg.bind, "bind", "127.0.0.1", "HTTP/WebSocket listen address")
	flag.IntVar(&cfg.port, "port", 8080, "HTTP/WebSocket listen port")
	flag.Float64Var(&cfg.replaySpeed, "replay-speed", 1.0, "timeline playback multiplier (replay mode)")
	flag.StringVar(&cfg.testdataDir, "testdata", "testdata", "directory holding replay timelines")
	flag.StringVar(&cfg.splunkURL, "splunk-url", "https://localhost:8089", "Splunk REST base URL (live mode)")
	flag.StringVar(&cfg.splunkToken, "splunk-token", "", "Splunk bearer token (live mode)")
	flag.StringVar(&cfg.splunkQuery, "splunk-search", "search index=sysmon", "Splunk search expression (live mode)")
	flag.StringVar(&cfg.splunkMCPURL, "splunk-mcp-url", "", "Splunk MCP Server endpoint URL; when set in live mode, narrator enrichment runs through the MCP server instead of REST")
	flag.StringVar(&cfg.splunkMCPToken, "splunk-mcp-token", "", "Splunk MCP Server bearer token (required when --splunk-mcp-url is set)")
	flag.BoolVar(&cfg.insecure, "insecure", false, "skip TLS verification for the Splunk endpoint")
	flag.Float64Var(&cfg.threshold, "threshold", 0.5, "scorer trigger threshold")
	flag.StringVar(&cfg.apiKey, "anthropic-key", os.Getenv("ANTHROPIC_API_KEY"), "Anthropic API key (omit to fall back to stub narrator)")
	flag.StringVar(&cfg.nvdKey, "nvd-key", os.Getenv("NVD_API_KEY"), "NVD API key to lift the CVE rate limit (live mode, optional)")
	flag.StringVar(&cfg.hecURL, "hec-url", "", "Splunk HEC base URL for chain result write-back, e.g. https://splunk:8088 (disabled when empty)")
	flag.StringVar(&cfg.hecToken, "hec-token", "", "Splunk HEC token (required when --hec-url is set)")
	flag.StringVar(&cfg.hecIndex, "hec-index", "", "Splunk index for HEC write-back (uses token default when empty)")
	flag.StringVar(&cfg.hecSourcetype, "hec-sourcetype", "causal_chain_result", "Splunk sourcetype for HEC write-back")
	flag.Parse()
	return cfg
}

func run(cfg config, logger *slog.Logger) error {
	source, err := buildSource(cfg)
	if err != nil {
		return fmt.Errorf("source: %w", err)
	}
	defer source.Close()

	narrator := buildNarrator(cfg, logger)
	intelAgent := buildIntelAgent(cfg, logger)

	g := graph.New()
	sc := scorer.New(scorer.Config{
		Threshold: cfg.threshold,
		SensitiveLabels: []string{
			"lsass.exe", "ntdsutil.exe", "secretsdump.py",
		},
	})

	bcast := api.NewBroadcaster()
	defer bcast.Close()

	hec, err := buildHEC(cfg, logger)
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

	server := api.NewServer(bcast, api.StaticFS())

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

func buildSource(cfg config) (splunk.Source, error) {
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
			return nil, fmt.Errorf("--splunk-token is required in live mode")
		}
		return splunk.NewRESTSource(splunk.RESTConfig{
			BaseURL:  cfg.splunkURL,
			Token:    cfg.splunkToken,
			Search:   cfg.splunkQuery,
			Insecure: cfg.insecure,
		}), nil
	default:
		return nil, fmt.Errorf("unknown --mode=%q (live | replay | ai-off)", cfg.mode)
	}
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
func buildHEC(cfg config, logger *slog.Logger) (pipeline.HECSink, error) {
	if cfg.hecURL == "" {
		return nil, nil
	}
	client, err := splunk.NewHECClient(splunk.HECConfig{
		URL:        cfg.hecURL,
		Token:      cfg.hecToken,
		Index:      cfg.hecIndex,
		Sourcetype: cfg.hecSourcetype,
		Insecure:   cfg.insecure,
	})
	if err != nil {
		return nil, err
	}
	logger.Info("HEC write-back enabled", "url", cfg.hecURL, "index", cfg.hecIndex, "sourcetype", cfg.hecSourcetype)
	return client, nil
}

func buildNarrator(cfg config, logger *slog.Logger) ai.Narrator {
	if cfg.mode == "ai-off" || cfg.apiKey == "" {
		if cfg.mode != "ai-off" {
			logger.Info("anthropic key not set, falling back to stub narrator")
		}
		return ai.NewStub()
	}
	var searcher ai.SplunkSearcher
	switch cfg.mode {
	case "live":
		if cfg.splunkMCPURL != "" {
			searcher = splunk.NewMCPSearcher(cfg.splunkMCPURL, cfg.splunkMCPToken, cfg.insecure)
			logger.Info("narrator enrichment via Splunk MCP Server", "mcp_url", cfg.splunkMCPURL)
		} else {
			searcher = splunk.NewRESTSearcher(cfg.splunkURL, cfg.splunkToken, cfg.insecure)
			logger.Info("narrator enrichment enabled", "splunk_url", cfg.splunkURL)
		}
	default:
		searcher = splunk.NewMockSearcher(cfg.testdataDir)
		logger.Info("narrator enrichment using mock fixtures", "testdata_dir", cfg.testdataDir)
	}
	return ai.NewClaude(ai.ClaudeConfig{APIKey: cfg.apiKey, Searcher: searcher})
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
	source := intel.NewRESTSource(intel.RESTConfig{NVDKey: cfg.nvdKey, Insecure: cfg.insecure})
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
