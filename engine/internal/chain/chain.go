// Package chain implements the weighted backward-walk chain extractor. When
// the scorer flags a hot node, Extract reconstructs the most likely causal
// path leading into it by repeatedly following the highest-scored incoming
// edge, returning the steps in chronological order plus a chain-level
// confidence (geometric mean of step confidences).
package chain

import (
	"math"
	"strings"

	"github.com/luigifernandez/unravel/engine/internal/graph"
	"github.com/luigifernandez/unravel/engine/internal/types"
)

// ScoreFn maps an edge ID to its current suspicion score. Passed in rather
// than depending on the scorer package directly so chain stays decoupled and
// trivially testable with a literal map.
type ScoreFn func(edgeID string) float64

// Extract walks backward from hotNodeID, choosing the highest-scored incoming
// edge at each step until no eligible predecessor remains. The returned steps
// are reversed into chronological order so the caller can render them as a
// narrative.
func Extract(g *graph.Graph, score ScoreFn, hotNodeID string) types.ChainResultPayload {
	visited := map[string]bool{hotNodeID: true}
	current := hotNodeID
	var reverse []types.ChainStep

	for {
		best := pickBestIncoming(g, current, score, visited)
		if best == nil {
			break
		}
		src := g.Node(best.Src)
		dst := g.Node(best.Dst)
		reverse = append(reverse, types.ChainStep{
			EventID:     best.SourceEventID,
			Description: describe(src, dst, best.Kind),
			Confidence:  best.Confidence,
			TS:          best.TS,
		})
		visited[best.Src] = true
		current = best.Src
	}

	steps := make([]types.ChainStep, len(reverse))
	for i, s := range reverse {
		steps[len(reverse)-1-i] = s
	}
	return types.ChainResultPayload{
		Confidence: geomMean(steps),
		Steps:      steps,
	}
}

func pickBestIncoming(g *graph.Graph, nodeID string, score ScoreFn, visited map[string]bool) *types.Edge {
	var best *types.Edge
	bestScore := math.Inf(-1)
	for _, e := range g.InEdges(nodeID) {
		if visited[e.Src] {
			continue
		}
		sc := score(e.ID)
		if sc > bestScore {
			bestScore = sc
			best = e
		}
	}
	return best
}

func describe(src, dst *types.Node, kind types.EdgeKind) string {
	verb := strings.ReplaceAll(string(kind), "_", " ")
	return labelOf(src) + " " + verb + " " + labelOf(dst)
}

func labelOf(n *types.Node) string {
	if n == nil {
		return ""
	}
	return n.Label
}

func geomMean(steps []types.ChainStep) float64 {
	if len(steps) == 0 {
		return 0
	}
	product := 1.0
	for _, s := range steps {
		product *= s.Confidence
	}
	return math.Pow(product, 1.0/float64(len(steps)))
}
