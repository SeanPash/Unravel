package ai

import (
	"context"
	"fmt"
	"strings"

	"github.com/luigifernandez/unravel/engine/internal/mitre"
	"github.com/luigifernandez/unravel/engine/internal/types"
)

// ThreatIntelAgent enriches a finished chain with external threat intelligence.
// Like Narrator, it is the AI seam: structured engine output in, structured
// findings out. Implementations own their own timeouts.
type ThreatIntelAgent interface {
	Enrich(ctx context.Context, chain types.ChainResultPayload) (types.ThreatIntelPayload, error)
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

func (a *DeterministicIntelAgent) Enrich(_ context.Context, chain types.ChainResultPayload) (types.ThreatIntelPayload, error) {
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
