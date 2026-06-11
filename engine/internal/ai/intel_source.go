package ai

import (
	"context"

	"github.com/luigifernandez/unravel/engine/internal/types"
)

// ThreatIntelSource is the network-bound half of threat enrichment. Technique
// intel (ATT&CK groups/software/mitigations) is NOT here: it comes from the
// bundled mitre snapshot in every mode. Implementations: intel.RESTSource
// (live), intel.MockSource (replay/test).
type ThreatIntelSource interface {
	KEV(ctx context.Context, keyword string) ([]types.CVEMatch, error)
	CVE(ctx context.Context, keyword string) ([]types.CVEMatch, error)
}
