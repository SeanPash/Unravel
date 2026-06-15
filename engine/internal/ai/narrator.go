// Package ai is the only LLM-touching component in the engine. It wraps a
// finished ChainResult plus the narrative-supporting metadata the pipeline
// already computed, and asks Gemini to produce a natural-language summary,
// hypotheses, and containment actions. All upstream subcomponents stay
// LLM-free; this is the seam where structured engine output meets the model.
package ai

import (
	"context"

	"github.com/luigifernandez/unravel/engine/internal/types"
)

// ActivityFunc receives one observational step from an agent's tool-use loop.
// It is the seam by which the narrator and threat-intel agent surface their
// progress to the UI without taking a dependency on the api/broadcaster
// package. It is passed per call (never stored on the agent) because one agent
// instance serves concurrent incidents; a stored emitter would race and
// interleave activity across incidents. A nil ActivityFunc is a valid no-op,
// so direct (non-pipeline) callers and tests may pass nil.
type ActivityFunc func(types.AgentActivityPayload)

// emit calls fn only when it is non-nil, so every emission site can stay a
// single unconditional call.
func (fn ActivityFunc) emit(a types.AgentActivityPayload) {
	if fn != nil {
		fn(a)
	}
}

// Narrator turns a chain extraction into a NarrationPayload. Implementations
// are responsible for their own timeouts and retries; callers run them under a
// context with a deadline. emit streams the agent's tool-use steps as they
// happen and may be nil.
type Narrator interface {
	Narrate(ctx context.Context, chain types.ChainResultPayload, emit ActivityFunc) (types.NarrationPayload, error)
}
