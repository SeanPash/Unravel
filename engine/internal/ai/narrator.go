// Package ai is the only LLM-touching component in the engine. It wraps a
// finished ChainResult plus the narrative-supporting metadata the pipeline
// already computed, and asks Claude to produce a natural-language summary,
// hypotheses, and containment actions. All upstream subcomponents stay
// LLM-free; this is the seam where structured engine output meets the model.
package ai

import (
	"context"

	"github.com/luigifernandez/unravel/engine/internal/types"
)

// Narrator turns a chain extraction into a NarrationPayload. Implementations
// are responsible for their own timeouts and retries; callers run them under a
// context with a deadline.
type Narrator interface {
	Narrate(ctx context.Context, chain types.ChainResultPayload) (types.NarrationPayload, error)
}
