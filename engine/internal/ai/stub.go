package ai

import (
	"context"
	"fmt"
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
			"Stub narrator output — wire ClaudeNarrator for production hypotheses.",
		},
		Actions: []string{
			"Review the highest-confidence chain step in the UI.",
		},
	}, nil
}
