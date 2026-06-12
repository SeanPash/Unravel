package ai

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/luigifernandez/unravel/engine/internal/types"
)

// StubNarrator returns a deterministic, templated narration synthesized from
// the chain itself. Used when `--mode=ai-off`, in unit tests, and in any demo
// environment that should not call the LLM.
type StubNarrator struct{}

// NewStub returns a ready-to-use StubNarrator.
func NewStub() *StubNarrator { return &StubNarrator{} }

// Narrate ignores the context (the stub never blocks) and renders a
// human-readable summary from the chain steps. The hypothesis and action lists
// are intentionally generic so callers can spot the stub output in the UI.
func (s *StubNarrator) Narrate(_ context.Context, chain types.ChainResultPayload) (types.NarrationPayload, error) {
	if len(chain.Steps) == 0 {
		return types.NarrationPayload{
			Text:    "No chain available to narrate.",
			Actions: []string{},
		}, nil
	}
	var parts []string
	for _, step := range chain.Steps {
		parts = append(parts, step.Description)
	}
	text := fmt.Sprintf("Detected a %d-step causal chain (confidence %.2f): %s.",
		len(chain.Steps), chain.Confidence, strings.Join(parts, "; "))
	return types.NarrationPayload{
		Text: text,
		Hypotheses: []string{
			"Stub narrator output: wire ClaudeNarrator for production hypotheses.",
		},
		Actions: []string{
			"Review the highest-confidence chain step in the UI.",
		},
		Phases: stubPhases(chain),
	}, nil
}

var nonSlugChars = regexp.MustCompile(`[^a-z0-9]+`)

// phaseSlug mirrors the UI's tactic-to-id mapping so stub phases line up with
// the structurally derived cards.
func phaseSlug(tactic string) string {
	return strings.Trim(nonSlugChars.ReplaceAllString(strings.ToLower(tactic), "-"), "-")
}

// stubPhases groups the chain steps by tactic, preserving first-event order,
// and writes a templated summary per phase. Steps without their own tactic
// are distributed across the chain's top-level tactic list in time order,
// matching the UI's display heuristic.
func stubPhases(chain types.ChainResultPayload) []types.NarrationPhase {
	steps := chain.Steps
	tagged := make([]types.ChainStep, 0, len(steps))
	for _, st := range steps {
		if st.Tactic != "" {
			tagged = append(tagged, st)
		}
	}
	if len(tagged) == 0 {
		if len(chain.Tactics) == 0 {
			return nil
		}
		n := len(chain.Tactics)
		if len(steps) < n {
			n = len(steps)
		}
		per := (len(steps) + n - 1) / n
		for i, st := range steps {
			idx := i / per
			if idx > n-1 {
				idx = n - 1
			}
			st.Tactic = chain.Tactics[idx]
			tagged = append(tagged, st)
		}
	}

	var order []string
	grouped := make(map[string][]types.ChainStep)
	for _, st := range tagged {
		if _, ok := grouped[st.Tactic]; !ok {
			order = append(order, st.Tactic)
		}
		grouped[st.Tactic] = append(grouped[st.Tactic], st)
	}

	phases := make([]types.NarrationPhase, 0, len(order))
	for _, tactic := range order {
		var descs []string
		for _, st := range grouped[tactic] {
			descs = append(descs, st.Description)
		}
		phases = append(phases, types.NarrationPhase{
			ID:      phaseSlug(tactic),
			Title:   tactic,
			Summary: strings.Join(descs, ". ") + ".",
		})
	}
	return phases
}
