package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/luigifernandez/unravel/engine/internal/mitre"
	"github.com/luigifernandez/unravel/engine/internal/types"
)

// ThreatIntelAgent enriches a finished chain with external threat intelligence.
// Like Narrator, it is the AI seam: structured engine output in, structured
// findings out. Implementations own their own timeouts. emit streams the
// agent's tool-use steps as they happen and may be nil.
type ThreatIntelAgent interface {
	Enrich(ctx context.Context, chain types.ChainResultPayload, emit ActivityFunc) (types.ThreatIntelPayload, error)
}

// chainTechniques returns the distinct technique IDs in chain order.
func chainTechniques(chain types.ChainResultPayload) []string {
	seen := map[string]bool{}
	var ids []string
	for _, s := range chain.Steps {
		if s.TechniqueID == "" || seen[s.TechniqueID] {
			continue
		}
		seen[s.TechniqueID] = true
		ids = append(ids, s.TechniqueID)
	}
	return ids
}

// techniqueIntelFromSnapshot builds a ThreatIntelTechnique from the bundled
// mitre snapshot, or a name-only stub if the technique is not in the snapshot.
func techniqueIntelFromSnapshot(id string) types.ThreatIntelTechnique {
	if ti, ok := mitre.Lookup(id); ok {
		return types.ThreatIntelTechnique{
			ID: ti.ID, Name: ti.Name,
			Groups: ti.Groups, Software: ti.Software, Mitigations: ti.Mitigations,
		}
	}
	return types.ThreatIntelTechnique{ID: id}
}

// DeterministicIntelAgent builds the payload purely from the bundled ATT&CK
// snapshot, with no LLM call. Used for --mode=ai-off, when no API key is set,
// and as a test double, so the Threat Intel tab is never empty.
type DeterministicIntelAgent struct{}

func NewDeterministicIntel() *DeterministicIntelAgent { return &DeterministicIntelAgent{} }

func (a *DeterministicIntelAgent) Enrich(_ context.Context, chain types.ChainResultPayload, emit ActivityFunc) (types.ThreatIntelPayload, error) {
	emit.emit(types.AgentActivityPayload{Kind: "done", Label: "ATT&CK snapshot only (no live enrichment)", Source: "MITRE ATT&CK"})
	ids := chainTechniques(chain)
	techs := make([]types.ThreatIntelTechnique, 0, len(ids))
	for _, id := range ids {
		techs = append(techs, techniqueIntelFromSnapshot(id))
	}
	return types.ThreatIntelPayload{
		Status:     "ok",
		Summary:    deterministicSummary(ids),
		Techniques: techs,
		CVEMatches: []types.CVEMatch{},
	}, nil
}

func deterministicSummary(ids []string) string {
	if len(ids) == 0 {
		return "No ATT&CK techniques were mapped for this chain."
	}
	return fmt.Sprintf(
		"This chain maps to %d ATT&CK technique(s): %s. Groups and mitigations below are drawn from the bundled ATT&CK reference data.",
		len(ids), strings.Join(ids, ", "),
	)
}

// GeminiIntelConfig configures the live threat-intel agent. APIKey is required.
type GeminiIntelConfig struct {
	APIKey     string
	Model      string
	BaseURL    string
	HTTPClient *http.Client
	MaxTokens  int
	Source     ThreatIntelSource
}

// GeminiIntelAgent correlates the chain's techniques against the bundled ATT&CK
// snapshot (lookup_technique_intel) plus live KEV/CVE (via Source), then writes
// a remediation summary. It reuses the narrator's Gemini tool-use plumbing.
type GeminiIntelAgent struct {
	cfg GeminiIntelConfig
}

func NewGeminiIntel(cfg GeminiIntelConfig) *GeminiIntelAgent {
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
	return &GeminiIntelAgent{cfg: cfg}
}

const intelSystemPrompt = `You are a threat-intelligence analyst. An upstream causal-graph engine reconstructed an attack chain and mapped its steps to MITRE ATT&CK techniques. Your job is to correlate those techniques against known threat intelligence and produce remediation guidance.

You have tools:
- lookup_technique_intel: ATT&CK groups, software/tooling, and mitigations for a technique ID (e.g. T1003.001). Call this for each distinct technique in the chain.
- lookup_kev: search the CISA Known Exploited Vulnerabilities catalog by keyword.
- search_cve: search the NVD CVE database by keyword.

Use the tools, then respond with a SINGLE JSON object, no surrounding prose, matching exactly:

{
  "status": "ok",
  "summary": <string, 2-4 sentence remediation-focused summary>,
  "techniques": [ { "id": <string>, "name": <string>, "groups": [<string>], "software": [<string>], "mitigations": [<string>] } ],
  "cve_matches": [ { "id": <string>, "summary": <string>, "in_kev": <bool>, "severity": <string> } ]
}

Include one techniques entry per distinct technique in the chain. Keep cve_matches to genuinely relevant entries; an empty array is fine.`

var intelToolDecls = []geminiFunctionDecl{
	{
		Name:        "lookup_technique_intel",
		Description: "ATT&CK groups, software, and mitigations for a technique ID.",
		Parameters: geminiSchema{
			Type:       "OBJECT",
			Properties: map[string]geminiSchema{"technique_id": {Type: "STRING", Description: "ATT&CK technique ID, e.g. T1003.001"}},
			Required:   []string{"technique_id"},
		},
	},
	{
		Name:        "lookup_kev",
		Description: "Search the CISA Known Exploited Vulnerabilities catalog by keyword.",
		Parameters: geminiSchema{
			Type:       "OBJECT",
			Properties: map[string]geminiSchema{"keyword": {Type: "STRING", Description: "Search term, e.g. kerberos"}},
			Required:   []string{"keyword"},
		},
	},
	{
		Name:        "search_cve",
		Description: "Search the NVD CVE database by keyword.",
		Parameters: geminiSchema{
			Type:       "OBJECT",
			Properties: map[string]geminiSchema{"keyword": {Type: "STRING", Description: "Search term, e.g. lsass"}},
			Required:   []string{"keyword"},
		},
	},
}

func (a *GeminiIntelAgent) Enrich(ctx context.Context, chain types.ChainResultPayload, emit ActivityFunc) (types.ThreatIntelPayload, error) {
	chainJSON, err := json.Marshal(chain)
	if err != nil {
		return types.ThreatIntelPayload{}, fmt.Errorf("marshal chain: %w", err)
	}
	contents := []geminiContent{{
		Role:  "user",
		Parts: []geminiPart{{Text: "Chain JSON:\n" + string(chainJSON)}},
	}}
	tools := []geminiTool{{FunctionDeclarations: intelToolDecls}}

	for i := 0; i < maxRounds; i++ {
		resp, err := generateContent(ctx, a.cfg.HTTPClient, a.cfg.BaseURL, a.cfg.APIKey, a.cfg.Model, geminiRequest{
			SystemInstruction: &geminiSystemInstruction{Parts: []geminiPart{{Text: intelSystemPrompt}}},
			Contents:          contents,
			Tools:             tools,
			GenerationConfig:  &geminiGenerationConfig{MaxOutputTokens: a.cfg.MaxTokens},
		})
		if err != nil {
			return types.ThreatIntelPayload{}, err
		}

		parts := candidateParts(resp)
		calls := functionCalls(parts)
		if len(calls) == 0 {
			payload, perr := parseIntel(extractText(parts))
			if perr != nil {
				return types.ThreatIntelPayload{}, perr
			}
			emit.emit(types.AgentActivityPayload{Kind: "done", Label: "Threat-intel correlation ready"})
			return payload, nil
		}

		contents = append(contents, geminiContent{Role: "model", Parts: parts})
		var responseParts []geminiPart
		for _, call := range calls {
			label, source := toolCallActivity(call.Name, call.Args)
			emit.emit(types.AgentActivityPayload{Kind: "tool_call", Tool: call.Name, Source: source, Label: label})
			content := a.dispatchIntelTool(ctx, call.Name, call.Args)
			detail, status := toolResultActivity(call.Name, content)
			emit.emit(types.AgentActivityPayload{Kind: "tool_result", Tool: call.Name, Source: source, Label: label, Detail: detail, Status: status})
			responseParts = append(responseParts, geminiPart{
				FunctionResponse: &geminiFunctionResponse{Name: call.Name, Response: toolResponseObject(content)},
			})
		}
		contents = append(contents, geminiContent{Role: "user", Parts: responseParts})
	}
	return types.ThreatIntelPayload{}, fmt.Errorf("intel agent exceeded %d rounds", maxRounds)
}

func (a *GeminiIntelAgent) dispatchIntelTool(ctx context.Context, name string, input map[string]any) string {
	switch name {
	case "lookup_technique_intel":
		id, _ := input["technique_id"].(string)
		ti := techniqueIntelFromSnapshot(id)
		b, _ := json.Marshal(ti)
		return string(b)
	case "lookup_kev":
		kw, _ := input["keyword"].(string)
		return a.cveResult(a.cfg.Source.KEV(ctx, kw))
	case "search_cve":
		kw, _ := input["keyword"].(string)
		return a.cveResult(a.cfg.Source.CVE(ctx, kw))
	default:
		return fmt.Sprintf(`{"error":"unknown tool: %s"}`, name)
	}
}

func (a *GeminiIntelAgent) cveResult(rows []types.CVEMatch, err error) string {
	if err != nil {
		return `{"error":"intel source unavailable"}`
	}
	b, _ := json.Marshal(map[string]any{"matches": rows})
	return string(b)
}

// parseIntel decodes the agent's final JSON, tolerating a markdown code fence,
// and normalizes nil slices so the JSON sent to the UI is well-formed.
func parseIntel(text string) (types.ThreatIntelPayload, error) {
	var out types.ThreatIntelPayload
	if err := json.Unmarshal([]byte(stripFence(text)), &out); err != nil {
		return types.ThreatIntelPayload{}, fmt.Errorf("decode intel JSON: %w", err)
	}
	if out.Status == "" {
		out.Status = "ok"
	}
	if out.Techniques == nil {
		out.Techniques = []types.ThreatIntelTechnique{}
	}
	if out.CVEMatches == nil {
		out.CVEMatches = []types.CVEMatch{}
	}
	return out, nil
}
