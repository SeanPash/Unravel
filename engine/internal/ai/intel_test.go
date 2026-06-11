package ai

import (
	"context"
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
	got, err := a.Enrich(context.Background(), sampleChain())
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
