package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luigifernandez/unravel/engine/internal/types"
)

func sampleChain() types.ChainResultPayload {
	return types.ChainResultPayload{
		Confidence: 0.9,
		Steps: []types.ChainStep{
			{Description: "winword spawned powershell", TechniqueID: "T1566.001", TechniqueName: "Spearphishing Attachment", Tactic: "Initial Access"},
			{Description: "powershell dumped lsass", TechniqueID: "T1003.001", TechniqueName: "LSASS Memory", Tactic: "Credential Access"},
			{Description: "second lsass access", TechniqueID: "T1003.001", TechniqueName: "LSASS Memory", Tactic: "Credential Access"},
		},
		Tactics: []string{"Initial Access", "Credential Access"},
	}
}

func TestDeterministicIntelDedupesAndPopulates(t *testing.T) {
	a := NewDeterministicIntel()
	got, err := a.Enrich(context.Background(), sampleChain(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "ok" {
		t.Errorf("status = %q", got.Status)
	}
	if len(got.Techniques) != 2 {
		t.Fatalf("techniques = %d, want 2 (deduped)", len(got.Techniques))
	}
	var lsass *types.ThreatIntelTechnique
	for i := range got.Techniques {
		if got.Techniques[i].ID == "T1003.001" {
			lsass = &got.Techniques[i]
		}
	}
	if lsass == nil || len(lsass.Software) == 0 {
		t.Fatalf("T1003.001 intel missing: %+v", got.Techniques)
	}
	if got.Summary == "" || !strings.Contains(got.Summary, "T1003.001") {
		t.Errorf("summary should reference techniques: %q", got.Summary)
	}
}

type stubIntelSource struct{}

func (stubIntelSource) KEV(_ context.Context, _ string) ([]types.CVEMatch, error) {
	return []types.CVEMatch{{ID: "CVE-2020-1472", Summary: "Zerologon", InKEV: true, Severity: "CRITICAL"}}, nil
}
func (stubIntelSource) CVE(_ context.Context, _ string) ([]types.CVEMatch, error) {
	return nil, nil
}

func TestClaudeIntelAgentRunsToolThenReturns(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		var resp claudeResponse
		if calls == 1 {
			resp = claudeResponse{Content: []claudeContentBlock{
				{Type: "tool_use", ID: "t1", Name: "lookup_kev", Input: map[string]any{"keyword": "kerberos"}},
			}}
		} else {
			final := `{"status":"ok","summary":"done","techniques":[{"id":"T1003.001","name":"LSASS Memory","groups":["APT29"],"software":["Mimikatz"],"mitigations":["RunAsPPL"]}],"cve_matches":[{"id":"CVE-2020-1472","summary":"Zerologon","in_kev":true,"severity":"CRITICAL"}]}`
			resp = claudeResponse{Content: []claudeContentBlock{{Type: "text", Text: final}}}
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	a := NewClaudeIntel(ClaudeIntelConfig{APIKey: "k", BaseURL: srv.URL, Source: stubIntelSource{}})
	got, err := a.Enrich(context.Background(), sampleChain(), nil)
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if calls != 2 {
		t.Errorf("expected 2 round trips (tool then final), got %d", calls)
	}
	if got.Status != "ok" || len(got.Techniques) != 1 || got.Techniques[0].ID != "T1003.001" {
		t.Errorf("parsed payload wrong: %+v", got)
	}
	if len(got.CVEMatches) != 1 || !got.CVEMatches[0].InKEV {
		t.Errorf("cve matches wrong: %+v", got.CVEMatches)
	}
}

func TestClaudeIntelAgentEmitsActivity(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		var resp claudeResponse
		if calls == 1 {
			resp = claudeResponse{Content: []claudeContentBlock{
				{Type: "tool_use", ID: "t1", Name: "lookup_kev", Input: map[string]any{"keyword": "kerberos"}},
			}}
		} else {
			resp = claudeResponse{Content: []claudeContentBlock{
				{Type: "text", Text: `{"status":"ok","summary":"done","techniques":[],"cve_matches":[]}`},
			}}
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	a := NewClaudeIntel(ClaudeIntelConfig{APIKey: "k", BaseURL: srv.URL, Source: stubIntelSource{}})
	var got []types.AgentActivityPayload
	emit := func(p types.AgentActivityPayload) { got = append(got, p) }
	if _, err := a.Enrich(context.Background(), sampleChain(), emit); err != nil {
		t.Fatalf("enrich: %v", err)
	}

	if len(got) != 3 {
		t.Fatalf("activity steps = %d, want 3 (tool_call, tool_result, done): %+v", len(got), got)
	}
	if got[0].Kind != "tool_call" || got[0].Source != "CISA KEV" {
		t.Errorf("step 0 = %+v, want tool_call from CISA KEV", got[0])
	}
	if got[1].Kind != "tool_result" || got[1].Status != "ok" {
		t.Errorf("step 1 = %+v, want ok tool_result", got[1])
	}
	if got[2].Kind != "done" {
		t.Errorf("step 2 = %+v, want done", got[2])
	}
}
