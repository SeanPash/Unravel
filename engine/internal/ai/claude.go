package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
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
	Searcher   SplunkSearcher
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

// Narrate sends the chain to Claude, dispatching tool calls until Claude
// produces a final end_turn response or maxRounds is exhausted. emit streams
// each tool call and result as it happens (nil disables streaming).
func (c *ClaudeNarrator) Narrate(ctx context.Context, chain types.ChainResultPayload, emit ActivityFunc) (types.NarrationPayload, error) {
	chainJSON, err := json.Marshal(chain)
	if err != nil {
		return types.NarrationPayload{}, fmt.Errorf("marshal chain: %w", err)
	}

	messages := []claudeMessage{{
		Role:    "user",
		Content: []claudeContentBlock{{Type: "text", Text: "Chain JSON:\n" + string(chainJSON)}},
	}}

	var tools []claudeTool
	if c.cfg.Searcher != nil {
		tools = narratorTools
	}

	for i := 0; i < maxRounds; i++ {
		resp, err := c.doRequest(ctx, claudeRequest{
			Model:     c.cfg.Model,
			MaxTokens: c.cfg.MaxTokens,
			System:    []claudeSystemBlock{{Type: "text", Text: systemPrompt, CacheControl: &claudeCacheControl{Type: "ephemeral"}}},
			Messages:  messages,
			Tools:     tools,
		})
		if err != nil {
			return types.NarrationPayload{}, err
		}

		hasToolUse := false
		for _, b := range resp.Content {
			if b.Type == "tool_use" {
				hasToolUse = true
				break
			}
		}

		if !hasToolUse {
			text := extractText(resp)
			if text == "" {
				return types.NarrationPayload{}, fmt.Errorf("claude returned no text content")
			}
			narr, perr := parseNarration(text)
			if perr != nil {
				return types.NarrationPayload{}, perr
			}
			emit.emit(types.AgentActivityPayload{Kind: "done", Label: "Narrative summary ready"})
			return narr, nil
		}

		messages = append(messages, claudeMessage{Role: "assistant", Content: resp.Content})
		var results []claudeContentBlock
		for _, b := range resp.Content {
			if b.Type != "tool_use" {
				continue
			}
			label, source := toolCallActivity(b.Name, b.Input)
			emit.emit(types.AgentActivityPayload{Kind: "tool_call", Tool: b.Name, Source: source, Label: label})
			content := c.dispatchTool(ctx, b.Name, b.Input)
			detail, status := toolResultActivity(b.Name, content)
			emit.emit(types.AgentActivityPayload{Kind: "tool_result", Tool: b.Name, Source: source, Label: label, Detail: detail, Status: status})
			results = append(results, claudeContentBlock{
				Type:      "tool_result",
				ToolUseID: b.ID,
				Content:   content,
			})
		}
		messages = append(messages, claudeMessage{Role: "user", Content: results})
	}

	return types.NarrationPayload{}, fmt.Errorf("narrator exceeded %d rounds without completing", maxRounds)
}

func (c *ClaudeNarrator) doRequest(ctx context.Context, reqBody claudeRequest) (claudeResponse, error) {
	return postMessages(ctx, c.cfg.HTTPClient, c.cfg.BaseURL, c.cfg.APIKey, reqBody)
}

// postMessages issues one Anthropic Messages request. Shared by ClaudeNarrator
// and ClaudeIntelAgent so the HTTP plumbing lives in one place.
func postMessages(ctx context.Context, httpClient *http.Client, baseURL, apiKey string, reqBody claudeRequest) (claudeResponse, error) {
	raw, err := json.Marshal(reqBody)
	if err != nil {
		return claudeResponse{}, fmt.Errorf("marshal request: %w", err)
	}

	endpoint := strings.TrimRight(baseURL, "/") + "/v1/messages"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return claudeResponse{}, err
	}
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("content-type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return claudeResponse{}, fmt.Errorf("claude request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return claudeResponse{}, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return claudeResponse{}, fmt.Errorf("claude status %d: %s", resp.StatusCode, body)
	}

	var decoded claudeResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return claudeResponse{}, fmt.Errorf("decode claude response: %w", err)
	}
	return decoded, nil
}

// systemPrompt is the static, cacheable preamble. Keeping the schema example
// inline (rather than templated) is intentional: any byte-level drift
// invalidates the cache.
const systemPrompt = `You are an incident-response analyst writing concise summaries of attack chains reconstructed by an upstream causal-graph engine. The engine sends you a JSON object with the following shape:

{
  "confidence": <float 0-1>,
  "steps": [
    { "event_id": <string>, "description": <string>, "confidence": <float>, "ts": <unix seconds>, "tactic": <optional MITRE ATT&CK tactic name> }
  ],
  "tactics": [<optional ordered MITRE ATT&CK tactic names>]
}

You MUST respond with a single JSON object, no surrounding prose, matching exactly this schema:

{
  "text": <string, 2-4 sentence narrative summary>,
  "hypotheses": [<string>, ...],
  "actions": [<string>, ...],
  "phases": [
    { "id": <string>, "title": <string>, "summary": <string, 1-2 sentence summary of this phase> }
  ]
}

Keep the narrative concrete and grounded in the supplied steps. Hypotheses are claims that go beyond the observed evidence; actions are short imperative containment steps an oncall responder can take immediately.

The phases array must contain exactly one entry per distinct tactic among the steps (or, when no step carries a tactic, per entry of the top-level tactics list), in chronological order. Each phase id must be the kebab-case form of the tactic name (for example "Credential Access" becomes "credential-access"); the title is the tactic name as given. Phase summaries describe only what that phase's steps show. Do not invent node identifiers, edge identifiers, timestamps, or confidence values; the engine attaches those to each phase itself.`

const maxRounds = 3

// narratorTools is the tool menu sent to Claude on every narration request.
// Tool definitions are static - they contribute to the cacheable prefix.
var narratorTools = []claudeTool{
	{
		Name:        "lookup_process_reputation",
		Description: "Look up whether a process name is flagged in the threat intelligence index.",
		InputSchema: claudeToolSchema{
			Type: "object",
			Properties: map[string]claudeSchemaProperty{
				"name": {Type: "string", Description: "Process image name, e.g. lsass.exe"},
			},
			Required: []string{"name"},
		},
	},
	{
		Name:        "get_account_logon_history",
		Description: "Retrieve recent Windows logon and failure events for a user account.",
		InputSchema: claudeToolSchema{
			Type: "object",
			Properties: map[string]claudeSchemaProperty{
				"username": {Type: "string", Description: "SAM account name, e.g. administrator"},
			},
			Required: []string{"username"},
		},
	},
	{
		Name:        "fetch_raw_events",
		Description: "Fetch raw log lines for specific Windows EventCode values from the chain steps.",
		InputSchema: claudeToolSchema{
			Type: "object",
			Properties: map[string]claudeSchemaProperty{
				"event_ids": {
					Type:        "array",
					Items:       &claudeSchemaProperty{Type: "string"},
					Description: "EventCode values from the chain steps, e.g. [\"1\",\"10\"]",
				},
			},
			Required: []string{"event_ids"},
		},
	},
	{
		Name:        "splunk_search",
		Description: "Run an arbitrary read-only SPL search against Splunk to gather additional evidence not covered by the other tools.",
		InputSchema: claudeToolSchema{
			Type: "object",
			Properties: map[string]claudeSchemaProperty{
				"spl": {Type: "string", Description: "A complete read-only SPL search, e.g. search index=sysmon EventCode=1 Image=*powershell* | head 20"},
			},
			Required: []string{"spl"},
		},
	},
}

// dispatchTool builds the SPL for name, runs it via the configured Searcher,
// and returns a JSON string suitable for a tool_result content block.
func (c *ClaudeNarrator) dispatchTool(ctx context.Context, name string, input map[string]any) string {
	query, err := buildSPL(name, input)
	if err != nil {
		return fmt.Sprintf(`{"error":%q}`, err.Error())
	}
	rows, err := c.cfg.Searcher.Search(ctx, query)
	if err != nil {
		return `{"error":"search unavailable"}`
	}
	b, _ := json.Marshal(map[string]any{"rows": rows})
	return string(b)
}

// buildSPL returns the SPL query for a given tool name and input parameters.
func buildSPL(name string, input map[string]any) (string, error) {
	switch name {
	case "lookup_process_reputation":
		n, _ := input["name"].(string)
		if n == "" {
			return "", fmt.Errorf("missing name")
		}
		return fmt.Sprintf(
			`search index=threat_intel process_name="%s" | head 5 | fields process_name,reputation,category,source`, n,
		), nil

	case "get_account_logon_history":
		u, _ := input["username"].(string)
		if u == "" {
			return "", fmt.Errorf("missing username")
		}
		return fmt.Sprintf(
			`search index=winsec (EventCode=4624 OR EventCode=4625) Account_Name="%s" earliest=-24h | head 20 | fields _time,EventCode,IpAddress,Workstation_Name`, u,
		), nil

	case "fetch_raw_events":
		ids, _ := input["event_ids"].([]any)
		if len(ids) == 0 {
			return "", fmt.Errorf("missing event_ids")
		}
		parts := make([]string, 0, len(ids))
		for _, id := range ids {
			if s, ok := id.(string); ok && s != "" {
				parts = append(parts, "EventCode="+s)
			}
		}
		if len(parts) == 0 {
			return "", fmt.Errorf("no valid event_ids")
		}
		return fmt.Sprintf(
			`search index=* (%s) | head 10 | fields _time,EventCode,host,source,_raw`,
			strings.Join(parts, " OR "),
		), nil

	case "splunk_search":
		spl, _ := input["spl"].(string)
		spl = strings.TrimSpace(spl)
		if spl == "" {
			return "", fmt.Errorf("missing spl")
		}
		if !isReadOnlySPL(spl) {
			return "", fmt.Errorf("refused: only read-only SPL is permitted")
		}
		return spl, nil

	default:
		return "", fmt.Errorf("unknown tool: %s", name)
	}
}

// pipeWS matches a pipe followed by any run of whitespace, so SPL command
// boundaries normalize to a bare "|cmd" regardless of spacing.
var pipeWS = regexp.MustCompile(`\|\s+`)

// isReadOnlySPL rejects SPL containing mutating or side-effecting commands. It
// normalizes whitespace after each pipe first, so "|  delete" and "| delete"
// both match. The Splunk MCP Server also validates input; this guard is
// defense-in-depth at the AI seam so the model cannot drive a destructive
// search through splunk_search.
func isReadOnlySPL(spl string) bool {
	normalized := pipeWS.ReplaceAllString(strings.ToLower(spl), "|")
	banned := []string{"|delete", "|outputlookup", "|outputcsv", "|collect", "|mcollect", "|tscollect", "|sendalert", "|runshellscript", "|script"}
	for _, b := range banned {
		if strings.Contains(normalized, b) {
			return false
		}
	}
	return true
}

type claudeCacheControl struct {
	Type string `json:"type"`
}

type claudeSystemBlock struct {
	Type         string              `json:"type"`
	Text         string              `json:"text"`
	CacheControl *claudeCacheControl `json:"cache_control,omitempty"`
}

type claudeContentBlock struct {
	Type      string         `json:"type"`
	Text      string         `json:"text,omitempty"`
	ID        string         `json:"id,omitempty"`
	Name      string         `json:"name,omitempty"`
	Input     map[string]any `json:"input,omitempty"`
	ToolUseID string         `json:"tool_use_id,omitempty"`
	Content   string         `json:"content,omitempty"`
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
	Tools     []claudeTool        `json:"tools,omitempty"`
}

type claudeTool struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	InputSchema claudeToolSchema `json:"input_schema"`
}

type claudeToolSchema struct {
	Type       string                          `json:"type"`
	Properties map[string]claudeSchemaProperty `json:"properties"`
	Required   []string                        `json:"required"`
}

type claudeSchemaProperty struct {
	Type        string                `json:"type"`
	Description string                `json:"description,omitempty"`
	Items       *claudeSchemaProperty `json:"items,omitempty"`
}

type claudeResponse struct {
	StopReason string               `json:"stop_reason"`
	Content    []claudeContentBlock `json:"content"`
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

// parseNarration is permissive: Claude occasionally wraps its JSON in a
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
