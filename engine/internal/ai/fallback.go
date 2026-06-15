package ai

import (
	"context"
	"log/slog"

	"github.com/luigifernandez/unravel/engine/internal/types"
)

// FallbackNarrator wraps a primary Narrator (the live Gemini narrator) and a
// secondary one (the deterministic stub). If the primary returns an error it
// logs the failure and returns the secondary's narration instead, so a transient
// model/API failure never leaves an incident with an empty narration panel. The
// activity emitter is forwarded to whichever narrator runs; a primary that emits
// some tool activity before failing simply leaves that partial trail in the feed
// before the stub's narration lands.
type FallbackNarrator struct {
	primary  Narrator
	fallback Narrator
	logger   *slog.Logger
}

// NewFallback wraps primary so that any error transparently degrades to
// fallback. It uses slog.Default() for the one warning it emits on degrade.
func NewFallback(primary, fallback Narrator) *FallbackNarrator {
	return &FallbackNarrator{primary: primary, fallback: fallback, logger: slog.Default()}
}

// Narrate runs the primary narrator and, on error, degrades to the fallback.
// The fallback's own error (the stub never errors in practice) is returned as-is
// so a total failure still surfaces rather than being masked.
func (f *FallbackNarrator) Narrate(ctx context.Context, chain types.ChainResultPayload, emit ActivityFunc) (types.NarrationPayload, error) {
	narr, err := f.primary.Narrate(ctx, chain, emit)
	if err == nil {
		return narr, nil
	}
	f.logger.Warn("primary narrator failed; degrading to stub narration", "err", err)
	return f.fallback.Narrate(ctx, chain, emit)
}
