// Package graph implements the engine's in-memory provenance graph: an
// incremental adjacency structure optimized for causal queries on streaming
// inputs. The full graph is broadcast to UI clients via Snapshot.
package graph

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luigifernandez/unravel/engine/internal/types"
)

// Graph holds nodes keyed by stable ID plus per-node in/out edge lists. Safe
// for concurrent reads and one writer (the pipeline goroutine).
type Graph struct {
	mu        sync.RWMutex
	nodes     map[string]*types.Node
	edges     map[string]*types.Edge
	outEdges  map[string][]*types.Edge
	inEdges   map[string][]*types.Edge
	edgeSeq   atomic.Uint64
	createdAt time.Time
}

// New returns an empty graph ready for streaming inserts.
func New() *Graph {
	return &Graph{
		nodes:     make(map[string]*types.Node),
		edges:     make(map[string]*types.Edge),
		outEdges:  make(map[string][]*types.Edge),
		inEdges:   make(map[string][]*types.Edge),
		createdAt: time.Now().UTC(),
	}
}

// nodePrefix returns the short ID prefix used for a given node kind. Keeps IDs
// readable in debug output and matches the WS schema's "proc-1234" style.
func nodePrefix(kind types.NodeKind) string {
	switch kind {
	case types.NodeKindProcess:
		return "proc"
	case types.NodeKindHost:
		return "host"
	case types.NodeKindUser:
		return "user"
	case types.NodeKindNetFlow:
		return "flow"
	default:
		return strings.ToLower(string(kind))
	}
}

// NodeID builds the deterministic ID used for FindOrCreateNode lookups. Exported
// so callers can construct edges referencing nodes they have not materialized.
func NodeID(kind types.NodeKind, key string) string {
	return nodePrefix(kind) + "-" + key
}

// FindOrCreateNode is idempotent: a repeat call with the same (kind, key)
// returns the existing node and leaves attrs untouched.
func (g *Graph) FindOrCreateNode(kind types.NodeKind, key, label string, attrs map[string]any) *types.Node {
	id := NodeID(kind, key)
	g.mu.Lock()
	defer g.mu.Unlock()
	if existing, ok := g.nodes[id]; ok {
		return existing
	}
	n := &types.Node{
		ID:    id,
		Kind:  kind,
		Label: label,
		Attrs: cloneAttrs(attrs),
	}
	g.nodes[id] = n
	return n
}

// AppendEdge inserts a new edge and updates both adjacency lists. Returns the
// stored *types.Edge so the caller can refer to it by ID later (e.g. scorer
// emits score_update messages keyed on edge.ID).
func (g *Graph) AppendEdge(src, dst *types.Node, kind types.EdgeKind, ts time.Time, confidence float64, srcEventID string) *types.Edge {
	g.mu.Lock()
	defer g.mu.Unlock()
	id := fmt.Sprintf("edge-%d", g.edgeSeq.Add(1))
	e := &types.Edge{
		ID:            id,
		Src:           src.ID,
		Dst:           dst.ID,
		Kind:          kind,
		TS:            ts.Unix(),
		Confidence:    confidence,
		SourceEventID: srcEventID,
	}
	g.edges[id] = e
	g.outEdges[src.ID] = append(g.outEdges[src.ID], e)
	g.inEdges[dst.ID] = append(g.inEdges[dst.ID], e)
	return e
}

// Node returns the node with the given ID, or nil if not present.
func (g *Graph) Node(id string) *types.Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.nodes[id]
}

// Edge returns the edge with the given ID, or nil if not present.
func (g *Graph) Edge(id string) *types.Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.edges[id]
}

// InEdges returns a copy of the incoming edge slice for the given node. Used by
// the chain extractor's backward walk.
func (g *Graph) InEdges(nodeID string) []*types.Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	src := g.inEdges[nodeID]
	if len(src) == 0 {
		return nil
	}
	out := make([]*types.Edge, len(src))
	copy(out, src)
	return out
}

// OutEdges returns a copy of the outgoing edge slice for the given node.
func (g *Graph) OutEdges(nodeID string) []*types.Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	src := g.outEdges[nodeID]
	if len(src) == 0 {
		return nil
	}
	out := make([]*types.Edge, len(src))
	copy(out, src)
	return out
}

// NodeCount returns the current node count. O(1).
func (g *Graph) NodeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.nodes)
}

// EdgeCount returns the current edge count. O(1).
func (g *Graph) EdgeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.edges)
}

// Snapshot returns a deep copy of the current graph suitable for broadcasting
// over the WebSocket without holding the graph lock for the duration of the
// send.
func (g *Graph) Snapshot() types.GraphUpdatePayload {
	g.mu.RLock()
	defer g.mu.RUnlock()
	nodes := make([]types.Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		nodes = append(nodes, types.Node{
			ID:    n.ID,
			Kind:  n.Kind,
			Label: n.Label,
			Attrs: cloneAttrs(n.Attrs),
		})
	}
	edges := make([]types.Edge, 0, len(g.edges))
	for _, e := range g.edges {
		edges = append(edges, *e)
	}
	return types.GraphUpdatePayload{Nodes: nodes, Edges: edges}
}

func cloneAttrs(src map[string]any) map[string]any {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]any, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}
