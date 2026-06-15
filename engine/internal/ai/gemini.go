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

// geminiAPIBase is the public Generative Language endpoint. Overridable via
// GeminiConfig.BaseURL for tests against an httptest.Server.
const geminiAPIBase = "https://generativelanguage.googleapis.com"

// geminiModel pins the hosted model the project uses. Override only via
// GeminiConfig.Model. Gemini Flash Lite applies implicit context caching to a
// stable prefix automatically, so the static system_instruction below is
// re-sent verbatim each turn and benefits from caching without an explicit
// cache directive.
const geminiModel = "gemini-3.1-flash-lite"

// maxRounds caps the tool-use loop for both the narrator and the intel agent.
const maxRounds = 3

// GeminiConfig configures the live narrator. APIKey is required; everything
// else has sensible defaults.
type GeminiConfig struct {
	APIKey     string
	Model      string
	BaseURL    string
	HTTPClient *http.Client
	MaxTokens  int
	Searcher   SplunkSearcher
	// SearcherName is the human label for the active Splunk backend (e.g.
	// "Splunk MCP Server"), used as the activity source for the splunk_search
	// tool so the feed honestly names the backend in use. Empty is fine.
	SearcherName string
	// NLGenerateSource is the human label for the backend that turns a
	// natural-language question into SPL: the live path is the Splunk AI
	// Assistant (SAIA) over the MCP Server; the replay path is a fixture-backed
	// simulation and must say so. Empty defaults to "Splunk MCP Server / SAIA".
	NLGenerateSource string
}

// GeminiNarrator calls the Gemini generateContent API with function-calling. A
// static system_instruction embeds the engine's output schema; each Narrate
// request sends only the chain JSON as user content, so the cacheable prefix
// stays identical across requests.
type GeminiNarrator struct {
	cfg GeminiConfig
}

// NewGemini returns a configured GeminiNarrator. Callers are expected to
// validate the API key during flag parsing; an empty key means the pipeline
// uses the deterministic stub instead of this narrator.
func NewGemini(cfg GeminiConfig) *GeminiNarrator {
	if cfg.Model == "" {
		cfg.Model = geminiModel
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = geminiAPIBase
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.MaxTokens <= 0 {
		cfg.MaxTokens = 2048
	}
	return &GeminiNarrator{cfg: cfg}
}

// Narrate sends the chain to Gemini, dispatching tool calls until the model
// produces a final text response or maxRounds is exhausted. emit streams each
// tool call and result as it happens (nil disables streaming).
func (c *GeminiNarrator) Narrate(ctx context.Context, chain types.ChainResultPayload, emit ActivityFunc) (types.NarrationPayload, error) {
	chainJSON, err := json.Marshal(chain)
	if err != nil {
		return types.NarrationPayload{}, fmt.Errorf("marshal chain: %w", err)
	}

	contents := []geminiContent{{
		Role:  "user",
		Parts: []geminiPart{{Text: "Chain JSON:\n" + string(chainJSON)}},
	}}

	var tools []geminiTool
	if decls := c.toolMenu(); len(decls) > 0 {
		tools = []geminiTool{{FunctionDeclarations: decls}}
	}

	for i := 0; i < maxRounds; i++ {
		resp, err := generateContent(ctx, c.cfg.HTTPClient, c.cfg.BaseURL, c.cfg.APIKey, c.cfg.Model, geminiRequest{
			SystemInstruction: &geminiSystemInstruction{Parts: []geminiPart{{Text: systemPrompt}}},
			Contents:          contents,
			Tools:             tools,
			GenerationConfig:  &geminiGenerationConfig{MaxOutputTokens: c.cfg.MaxTokens},
		})
		if err != nil {
			return types.NarrationPayload{}, err
		}

		parts := candidateParts(resp)
		calls := functionCalls(parts)

		if len(calls) == 0 {
			text := extractText(parts)
			if text == "" {
				return types.NarrationPayload{}, fmt.Errorf("gemini returned no text content")
			}
			narr, perr := parseNarration(text)
			if perr != nil {
				return types.NarrationPayload{}, perr
			}
			emit.emit(types.AgentActivityPayload{Kind: "done", Label: "Narrative summary ready"})
			return narr, nil
		}

		// Echo the model's function-call turn back, then answer each call.
		contents = append(contents, geminiContent{Role: "model", Parts: parts})
		var responseParts []geminiPart
		for _, call := range calls {
			var content string
			if call.Name == "splunk_nl_search" {
				// splunk_nl_search makes two MCP calls (generate, then run) and
				// owns its own activity emission so the feed names both backends.
				content = c.dispatchNLSearch(ctx, call.Args, emit)
			} else {
				label, source := toolCallActivity(call.Name, call.Args)
				if call.Name == "splunk_search" && c.cfg.SearcherName != "" {
					source = c.cfg.SearcherName
				}
				emit.emit(types.AgentActivityPayload{Kind: "tool_call", Tool: call.Name, Source: source, Label: label})
				content = c.dispatchTool(ctx, call.Name, call.Args)
				detail, status := toolResultActivity(call.Name, content)
				emit.emit(types.AgentActivityPayload{Kind: "tool_result", Tool: call.Name, Source: source, Label: label, Detail: detail, Status: status})
			}
			responseParts = append(responseParts, geminiPart{
				FunctionResponse: &geminiFunctionResponse{Name: call.Name, Response: toolResponseObject(content)},
			})
		}
		contents = append(contents, geminiContent{Role: "user", Parts: responseParts})
	}

	return types.NarrationPayload{}, fmt.Errorf("narrator exceeded %d rounds without completing", maxRounds)
}

// systemPrompt is the static, cacheable preamble. It defines the engine input
// shape and pins the structured incident report the narrator must return.
const systemPrompt = `You are a senior incident-response analyst. An upstream causal-graph engine has already reconstructed an attack chain from Splunk telemetry and mapped it to MITRE ATT&CK. You receive a JSON object:

{
  "confidence": <float 0-1>,
  "steps": [ { "event_id": <string>, "description": <string>, "confidence": <float>, "ts": <unix seconds>, "tactic": <optional ATT&CK tactic name> } ],
  "tactics": [<optional ordered ATT&CK tactic names>]
}

You have read-only tools to gather corroborating evidence from Splunk and threat intelligence. Use them deliberately: before you finalize, pull at least one piece of corroborating evidence for the most severe step in the chain (for example, look up the reputation of the process that dumped credentials, or pull the logon history for the account that reached the domain controller). Prefer the natural-language Splunk search when it is offered. Never invent data you did not retrieve, and never state as fact anything a tool did not confirm; downgrade unconfirmed claims to hypotheses.

Respond with a SINGLE JSON object, no surrounding prose, matching EXACTLY this schema:

{
  "text": <string, a 2-4 sentence executive summary a manager can read>,
  "severity": <one of "low" | "medium" | "high" | "critical">,
  "key_findings": [<string>, ...],
  "affected_assets": [<string>, ...],
  "hypotheses": [<string>, ...],
  "actions": [ { "priority": <"immediate" | "high" | "medium" | "low">, "action": <string>, "rationale": <string> } ],
  "phases": [ { "id": <string>, "title": <string>, "summary": <string, 1-2 sentences> } ]
}

Field rules:
- text: a tight 2-4 sentence causal story - how the attack started, how it progressed step to step, and where it ended up - written so a duty manager understands the impact without reading the graph. State the through-line (entry point -> escalation -> objective), not a list of events. No jargon dumps.
- severity: grounded in observed impact. Domain-controller compromise or credential theft is high or critical; isolated reconnaissance is low or medium.
- key_findings: the handful of observations that matter most, each concrete and tied to specific evidence in the steps - name the exact process, host, account, and the ATT&CK technique id and name where the step carries one (for example "powershell.exe on WS01 read lsass.exe memory (T1003.001 OS Credential Dumping: LSASS Memory)"). Most important first. Cite tool results when a tool corroborated the finding.
- affected_assets: the distinct hosts, accounts, and processes implicated, as short identifiers (for example "WS01", "administrator", "lsass.exe"). Only assets that actually appear in the steps or tool results.
- hypotheses: specific, testable claims that go beyond the observed evidence and name the concrete next check - tie each to a real node, account, or technique in this chain (for example "the same Kerberos ticket may have authenticated to other hosts - pull 4769 events for NORTHPOLE\\Administrator across the domain"). Frame as suspected but unconfirmed. Do not pad with generic advice.
- actions: prioritized, imperative containment steps an oncall responder can take now, each naming the specific asset or account from this chain. Each entry has a priority, the action, and a one-line rationale tying it to the observed activity. Order with "immediate" first.
- phases: exactly one entry per distinct tactic among the steps (or per entry of the top-level tactics list when no step carries a tactic), in chronological order. The id is the kebab-case tactic name ("Credential Access" becomes "credential-access"); the title is the tactic name as given; the summary describes only that phase's steps.

Stay concrete and grounded in the supplied steps and tool results. Do NOT invent node ids, edge ids, timestamps, or confidence values - the engine attaches those itself. Do NOT add a disclaimer field - the engine attaches the honesty notice itself.`

// narratorToolDecls is the function-declaration menu sent to Gemini on every
// narration request. The declarations are static, so they form part of the
// stable prefix that implicit caching rewards.
var narratorToolDecls = []geminiFunctionDecl{
	{
		Name:        "lookup_process_reputation",
		Description: "Look up whether a process name is flagged in the threat intelligence index.",
		Parameters: geminiSchema{
			Type: "OBJECT",
			Properties: map[string]geminiSchema{
				"name": {Type: "STRING", Description: "Process image name, e.g. lsass.exe"},
			},
			Required: []string{"name"},
		},
	},
	{
		Name:        "get_account_logon_history",
		Description: "Retrieve recent Windows logon and failure events for a user account.",
		Parameters: geminiSchema{
			Type: "OBJECT",
			Properties: map[string]geminiSchema{
				"username": {Type: "STRING", Description: "SAM account name, e.g. administrator"},
			},
			Required: []string{"username"},
		},
	},
	{
		Name:        "fetch_raw_events",
		Description: "Fetch raw log lines for specific Windows EventCode values from the chain steps.",
		Parameters: geminiSchema{
			Type: "OBJECT",
			Properties: map[string]geminiSchema{
				"event_ids": {
					Type:        "ARRAY",
					Items:       &geminiSchema{Type: "STRING"},
					Description: "EventCode values from the chain steps, e.g. [\"1\",\"10\"]",
				},
			},
			Required: []string{"event_ids"},
		},
	},
	{
		Name:        "splunk_search",
		Description: "Run an arbitrary read-only SPL search against Splunk to gather additional evidence not covered by the other tools.",
		Parameters: geminiSchema{
			Type: "OBJECT",
			Properties: map[string]geminiSchema{
				"spl": {Type: "STRING", Description: "A complete read-only SPL search, e.g. search index=sysmon EventCode=1 Image=*powershell* | head 20"},
			},
			Required: []string{"spl"},
		},
	},
}

// splunkNLSearchDecl is offered only when the configured Searcher implements
// SPLGenerator (live+MCP mode). It is appended to the menu, never part of the
// static narratorToolDecls, so the menu stays constant within a mode.
var splunkNLSearchDecl = geminiFunctionDecl{
	Name:        "splunk_nl_search",
	Description: "Ask Splunk's AI Assistant to turn a natural-language question into SPL and run it, to gather evidence the other tools do not cover. Provide a plain-English question, e.g. \"which accounts logged into the domain controller in the last hour?\".",
	Parameters: geminiSchema{
		Type: "OBJECT",
		Properties: map[string]geminiSchema{
			"question": {Type: "STRING", Description: "A natural-language question about the environment, e.g. \"show recent failed logons for administrator\""},
		},
		Required: []string{"question"},
	},
}

// toolMenu returns the function declarations for this narrator. The four base
// tools require a Searcher; splunk_nl_search is appended only when that Searcher
// also implements SPLGenerator (live+MCP mode). The menu is therefore constant
// within a run mode, keeping the cached system+tools prefix stable.
func (c *GeminiNarrator) toolMenu() []geminiFunctionDecl {
	if c.cfg.Searcher == nil {
		return nil
	}
	if _, ok := c.cfg.Searcher.(SPLGenerator); ok {
		menu := make([]geminiFunctionDecl, len(narratorToolDecls), len(narratorToolDecls)+1)
		copy(menu, narratorToolDecls)
		return append(menu, splunkNLSearchDecl)
	}
	return narratorToolDecls
}

// dispatchTool builds the SPL for name, runs it via the configured Searcher,
// and returns a JSON string suitable for a functionResponse part.
func (c *GeminiNarrator) dispatchTool(ctx context.Context, name string, input map[string]any) string {
	query, err := buildSPL(name, input)
	if err != nil {
		return fmt.Sprintf(`{"error":%q}`, err.Error())
	}
	// Central read-only guard: every search-running tool funnels through here,
	// so the curated tools are checked as strictly as splunk_search. This is the
	// only place a query reaches Searcher.Search from this method, so no tool can
	// bypass the allowlist.
	if !isReadOnlySPL(query) {
		return `{"error":"refused: only read-only SPL is permitted"}`
	}
	rows, err := c.cfg.Searcher.Search(ctx, query)
	if err != nil {
		return `{"error":"search unavailable"}`
	}
	b, _ := json.Marshal(map[string]any{"rows": rows})
	return string(b)
}

// nlSearchRunSource is the activity source for the run sub-step: the MCP backend
// that executes the AI-generated SPL. Falls back to a literal when SearcherName
// is unset (it is set to "Splunk MCP Server" in live+MCP mode).
func (c *GeminiNarrator) nlSearchRunSource() string {
	if c.cfg.SearcherName != "" {
		return c.cfg.SearcherName
	}
	return "Splunk MCP Server"
}

// dispatchNLSearch handles the splunk_nl_search tool: it asks the Splunk AI
// Assistant to generate SPL from the question, guards it read-only, runs it via
// the Searcher, and returns a {generated_spl, rows} tool result. It emits its
// own two activity sub-steps (AI Assistant generate, then MCP run) so the feed
// honestly names both backends, and degrades to an error result at each failure
// point without affecting the narrator's other tools.
func (c *GeminiNarrator) dispatchNLSearch(ctx context.Context, input map[string]any, emit ActivityFunc) string {
	gen, ok := c.cfg.Searcher.(SPLGenerator)
	if !ok {
		return `{"error":"nl search unavailable"}`
	}
	question, _ := input["question"].(string)
	question = strings.TrimSpace(question)
	if question == "" {
		return `{"error":"missing question"}`
	}

	genSource := c.cfg.NLGenerateSource
	if genSource == "" {
		genSource = "Splunk MCP Server / SAIA"
	}
	genLabel := nlGenerateLabel(question)
	emit.emit(types.AgentActivityPayload{Kind: "tool_call", Tool: "splunk_nl_search", Source: genSource, Label: genLabel})

	spl, err := gen.GenerateSPL(ctx, question)
	if err != nil {
		emit.emit(types.AgentActivityPayload{Kind: "tool_result", Tool: "splunk_nl_search", Source: genSource, Label: genLabel, Detail: "SPL generation unavailable", Status: "error"})
		return `{"error":"spl generation unavailable"}`
	}
	spl = strings.TrimSpace(spl)
	if spl == "" {
		emit.emit(types.AgentActivityPayload{Kind: "tool_result", Tool: "splunk_nl_search", Source: genSource, Label: genLabel, Detail: "AI Assistant returned no SPL", Status: "error"})
		return `{"error":"ai assistant returned no spl"}`
	}
	if !isReadOnlySPL(spl) {
		emit.emit(types.AgentActivityPayload{Kind: "tool_result", Tool: "splunk_nl_search", Source: genSource, Label: genLabel, Detail: "refused: generated SPL is not read-only", Status: "error"})
		return `{"error":"refused: only read-only SPL is permitted"}`
	}
	emit.emit(types.AgentActivityPayload{Kind: "tool_result", Tool: "splunk_nl_search", Source: genSource, Label: genLabel, Detail: truncate(spl, 80), Status: "ok"})

	runSource := c.nlSearchRunSource()
	const runLabel = "Running AI-generated SPL"
	emit.emit(types.AgentActivityPayload{Kind: "tool_call", Tool: "splunk_nl_search", Source: runSource, Label: runLabel})
	rows, err := c.cfg.Searcher.Search(ctx, spl)
	if err != nil {
		emit.emit(types.AgentActivityPayload{Kind: "tool_result", Tool: "splunk_nl_search", Source: runSource, Label: runLabel, Detail: "search unavailable", Status: "error"})
		return `{"error":"search unavailable"}`
	}
	detail, status := nlRunResult(rows)
	emit.emit(types.AgentActivityPayload{Kind: "tool_result", Tool: "splunk_nl_search", Source: runSource, Label: runLabel, Detail: detail, Status: status})

	b, _ := json.Marshal(map[string]any{"generated_spl": spl, "rows": rows})
	return string(b)
}

// generateContent issues one Gemini generateContent request. Shared by the
// narrator and the intel agent so the HTTP plumbing lives in one place.
func generateContent(ctx context.Context, httpClient *http.Client, baseURL, apiKey, model string, reqBody geminiRequest) (geminiResponse, error) {
	raw, err := json.Marshal(reqBody)
	if err != nil {
		return geminiResponse{}, fmt.Errorf("marshal request: %w", err)
	}

	endpoint := fmt.Sprintf("%s/v1beta/models/%s:generateContent", strings.TrimRight(baseURL, "/"), model)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return geminiResponse{}, err
	}
	req.Header.Set("x-goog-api-key", apiKey)
	req.Header.Set("content-type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return geminiResponse{}, fmt.Errorf("gemini request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return geminiResponse{}, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return geminiResponse{}, fmt.Errorf("gemini status %d: %s", resp.StatusCode, body)
	}

	var decoded geminiResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return geminiResponse{}, fmt.Errorf("decode gemini response: %w", err)
	}
	return decoded, nil
}

// toolResponseObject turns a tool's JSON-string result into the object Gemini
// expects in a functionResponse part. Non-JSON output is wrapped so the model
// still receives well-formed content.
func toolResponseObject(content string) map[string]any {
	var m map[string]any
	if err := json.Unmarshal([]byte(content), &m); err == nil {
		return m
	}
	return map[string]any{"output": content}
}

// --- Gemini wire types ---

type geminiPart struct {
	Text string `json:"text,omitempty"`
	// ThoughtSignature is an opaque token Gemini 3.x thinking models attach to the
	// part carrying a functionCall. It MUST be echoed back verbatim when the model
	// turn is replayed in the conversation history, or the next tool-use round is
	// rejected with HTTP 400 ("Function call is missing a thought_signature").
	// Capturing it here lets the part round-trip unchanged. See
	// https://ai.google.dev/gemini-api/docs/thought-signatures
	ThoughtSignature string                  `json:"thoughtSignature,omitempty"`
	FunctionCall     *geminiFunctionCall     `json:"functionCall,omitempty"`
	FunctionResponse *geminiFunctionResponse `json:"functionResponse,omitempty"`
}

type geminiFunctionCall struct {
	Name string         `json:"name"`
	Args map[string]any `json:"args,omitempty"`
}

type geminiFunctionResponse struct {
	Name     string         `json:"name"`
	Response map[string]any `json:"response"`
}

type geminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []geminiPart `json:"parts"`
}

type geminiSystemInstruction struct {
	Parts []geminiPart `json:"parts"`
}

type geminiTool struct {
	FunctionDeclarations []geminiFunctionDecl `json:"functionDeclarations"`
}

type geminiFunctionDecl struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Parameters  geminiSchema `json:"parameters"`
}

// geminiSchema is the OpenAPI-subset schema Gemini accepts for function
// parameters. Type values are uppercase ("OBJECT", "STRING", "ARRAY").
type geminiSchema struct {
	Type        string                  `json:"type"`
	Description string                  `json:"description,omitempty"`
	Properties  map[string]geminiSchema `json:"properties,omitempty"`
	Items       *geminiSchema           `json:"items,omitempty"`
	Required    []string                `json:"required,omitempty"`
}

type geminiGenerationConfig struct {
	MaxOutputTokens int `json:"maxOutputTokens,omitempty"`
}

type geminiRequest struct {
	SystemInstruction *geminiSystemInstruction `json:"system_instruction,omitempty"`
	Contents          []geminiContent          `json:"contents"`
	Tools             []geminiTool             `json:"tools,omitempty"`
	GenerationConfig  *geminiGenerationConfig  `json:"generationConfig,omitempty"`
}

type geminiResponse struct {
	Candidates []geminiCandidate `json:"candidates"`
}

type geminiCandidate struct {
	Content      geminiContent `json:"content"`
	FinishReason string        `json:"finishReason,omitempty"`
}

// candidateParts returns the parts of the first candidate, or nil when the
// response carries no candidates.
func candidateParts(r geminiResponse) []geminiPart {
	if len(r.Candidates) == 0 {
		return nil
	}
	return r.Candidates[0].Content.Parts
}

// functionCalls extracts every functionCall part, in order.
func functionCalls(parts []geminiPart) []geminiFunctionCall {
	var calls []geminiFunctionCall
	for _, p := range parts {
		if p.FunctionCall != nil {
			calls = append(calls, *p.FunctionCall)
		}
	}
	return calls
}

// extractText concatenates every text part of a response.
func extractText(parts []geminiPart) string {
	var b strings.Builder
	for _, p := range parts {
		if p.Text != "" {
			b.WriteString(p.Text)
		}
	}
	return strings.TrimSpace(b.String())
}

// stripFence removes a surrounding markdown code fence the model occasionally
// adds even when told not to, so the JSON inside can be decoded.
func stripFence(text string) string {
	body := strings.TrimSpace(text)
	body = strings.TrimPrefix(body, "```json")
	body = strings.TrimPrefix(body, "```")
	body = strings.TrimSuffix(body, "```")
	return strings.TrimSpace(body)
}

// parseNarration decodes the narrator's final JSON, tolerating a markdown code
// fence, and normalizes nil slices so the payload sent to the UI is well-formed.
func parseNarration(text string) (types.NarrationPayload, error) {
	var out types.NarrationPayload
	if err := json.Unmarshal([]byte(stripFence(text)), &out); err != nil {
		return types.NarrationPayload{}, fmt.Errorf("decode narration JSON: %w", err)
	}
	// Drop blank list entries the model occasionally emits (an empty string, or
	// an action object missing its fields after schema drift). An empty action
	// would otherwise render in the UI as a bare priority badge with no text, so
	// the report stays clean regardless of what the model returned.
	out.KeyFindings = nonEmptyStrings(out.KeyFindings)
	out.AffectedAssets = nonEmptyStrings(out.AffectedAssets)
	out.Hypotheses = nonEmptyStrings(out.Hypotheses)
	out.Actions = nonEmptyActions(out.Actions)
	// The disclaimer is engine-authored, not model-authored, so the honesty
	// caveat is always present and worded consistently regardless of what the
	// model returned (it is told not to emit one).
	out.Disclaimer = NarrationDisclaimer
	return out, nil
}

// nonEmptyStrings returns a new, never-nil slice containing only the trimmed,
// non-blank entries of in. Never-nil so the JSON payload stays well-formed
// (an empty array, not null) for the UI.
func nonEmptyStrings(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

// nonEmptyActions returns a new, never-nil slice of the actions that carry
// actual instruction text, dropping zero-value entries the model can emit when
// its output drifts from the action schema.
func nonEmptyActions(in []types.NarrationAction) []types.NarrationAction {
	out := make([]types.NarrationAction, 0, len(in))
	for _, a := range in {
		if strings.TrimSpace(a.Action) != "" {
			out = append(out, a)
		}
	}
	return out
}
