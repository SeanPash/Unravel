package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/luigifernandez/unravel/engine/internal/types"
)

// claudeAPIBase is the public Messages endpoint. Overridable via
// ClaudeConfig.BaseURL for tests against an httptest.Server.
const claudeAPIBase = "https://api.anthropic.com"

// claudeModel pins the model the project committed to in CLAUDE.md
// (Locked Design Decisions). Override only via ClaudeConfig.Model.
const claudeModel = "claude-sonnet-4-6"

// ClaudeConfig configures the live narrator. APIKey is required; everything
// else has sensible defaults.
type ClaudeConfig struct {
	APIKey     string
	Model      string
	BaseURL    string
	HTTPClient *http.Client
	MaxTokens  int
}

// ClaudeNarrator calls the Anthropic Messages API with prompt caching enabled
// on a static system prompt that embeds the engine's output schema. Each
// Narrate request sends only the chain JSON as user content, keeping the
// cacheable prefix bit-identical across requests for cache hit rates.
type ClaudeNarrator struct {
	cfg ClaudeConfig
}

// NewClaude returns a configured ClaudeNarrator. Panics only on nil APIKey
// because the misconfiguration is unambiguous; callers are expected to validate
// the API key during flag parsing.
func NewClaude(cfg ClaudeConfig) *ClaudeNarrator {
	if cfg.Model == "" {
		cfg.Model = claudeModel
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = claudeAPIBase
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.MaxTokens <= 0 {
		cfg.MaxTokens = 1024
	}
	return &ClaudeNarrator{cfg: cfg}
}

// Narrate sends the chain to Claude and decodes the structured response.
func (c *ClaudeNarrator) Narrate(ctx context.Context, chain types.ChainResultPayload) (types.NarrationPayload, error) {
	chainJSON, err := json.Marshal(chain)
	if err != nil {
		return types.NarrationPayload{}, fmt.Errorf("marshal chain: %w", err)
	}

	reqBody := claudeRequest{
		Model:     c.cfg.Model,
		MaxTokens: c.cfg.MaxTokens,
		System: []claudeSystemBlock{
			{
				Type:         "text",
				Text:         systemPrompt,
				CacheControl: &claudeCacheControl{Type: "ephemeral"},
			},
		},
		Messages: []claudeMessage{
			{
				Role: "user",
				Content: []claudeContentBlock{
					{Type: "text", Text: "Chain JSON:\n" + string(chainJSON)},
				},
			},
		},
	}

	raw, err := json.Marshal(reqBody)
	if err != nil {
		return types.NarrationPayload{}, fmt.Errorf("marshal request: %w", err)
	}

	endpoint := strings.TrimRight(c.cfg.BaseURL, "/") + "/v1/messages"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return types.NarrationPayload{}, err
	}
	req.Header.Set("x-api-key", c.cfg.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("content-type", "application/json")

	resp, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		return types.NarrationPayload{}, fmt.Errorf("claude request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return types.NarrationPayload{}, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return types.NarrationPayload{}, fmt.Errorf("claude status %d: %s", resp.StatusCode, body)
	}

	var decoded claudeResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return types.NarrationPayload{}, fmt.Errorf("decode claude response: %w", err)
	}

	text := extractText(decoded)
	if text == "" {
		return types.NarrationPayload{}, fmt.Errorf("claude returned no text content")
	}
	return parseNarration(text)
}

// systemPrompt is the static, cacheable preamble. Keeping the schema example
// inline (rather than templated) is intentional: any byte-level drift
// invalidates the cache.
const systemPrompt = `You are an incident-response analyst writing concise summaries of attack chains reconstructed by an upstream causal-graph engine. The engine sends you a JSON object with the following shape:

{
  "confidence": <float 0-1>,
  "steps": [
    { "event_id": <string>, "description": <string>, "confidence": <float>, "ts": <unix seconds> }
  ]
}

You MUST respond with a single JSON object, no surrounding prose, matching exactly this schema:

{
  "text": <string, 2-4 sentence narrative summary>,
  "hypotheses": [<string>, ...],
  "actions": [<string>, ...]
}

Keep the narrative concrete and grounded in the supplied steps. Hypotheses are claims that go beyond the observed evidence; actions are short imperative containment steps an oncall responder can take immediately.`

type claudeCacheControl struct {
	Type string `json:"type"`
}

type claudeSystemBlock struct {
	Type         string              `json:"type"`
	Text         string              `json:"text"`
	CacheControl *claudeCacheControl `json:"cache_control,omitempty"`
}

type claudeContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type claudeMessage struct {
	Role    string               `json:"role"`
	Content []claudeContentBlock `json:"content"`
}

type claudeRequest struct {
	Model     string              `json:"model"`
	MaxTokens int                 `json:"max_tokens"`
	System    []claudeSystemBlock `json:"system"`
	Messages  []claudeMessage     `json:"messages"`
}

type claudeResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
}

func extractText(r claudeResponse) string {
	var b strings.Builder
	for _, c := range r.Content {
		if c.Type == "text" {
			b.WriteString(c.Text)
		}
	}
	return strings.TrimSpace(b.String())
}

// parseNarration is permissive — Claude occasionally wraps its JSON in a
// markdown code fence even when told not to, so we strip fences before
// decoding.
func parseNarration(text string) (types.NarrationPayload, error) {
	body := strings.TrimSpace(text)
	body = strings.TrimPrefix(body, "```json")
	body = strings.TrimPrefix(body, "```")
	body = strings.TrimSuffix(body, "```")
	body = strings.TrimSpace(body)

	var out types.NarrationPayload
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		return types.NarrationPayload{}, fmt.Errorf("decode narration JSON: %w", err)
	}
	if out.Hypotheses == nil {
		out.Hypotheses = []string{}
	}
	if out.Actions == nil {
		out.Actions = []string{}
	}
	return out, nil
}
