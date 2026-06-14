// Package graph implements the engine's in-memory provenance graph: an
// incremental adjacency structure optimized for causal queries on streaming
// inputs. The full graph is broadcast to UI clients via Snapshot.
package graph

import (
	"fmt"
	"sort"
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

	// nodeLastSeen records, per node ID, a monotonic *logical* touch sequence
	// (not a timestamp) that advances every time the node is created or touched
	// by an incident edge. It drives least-recently-touched ordering for
	// retention eviction. types.Node carries no recency of its own, so this
	// internal map supplies one without touching the shared types package.
	//
	// A logical sequence is used deliberately instead of the edge event time:
	// it tracks arrival order (the order the pipeline actually processed events)
	// and is therefore immune to the wall-clock-vs-event-time mismatch that bit
	// an earlier version. A node kept warm by a stream of recent edges always
	// ranks newer than an idle one, even when the engine replays historical
	// events whose timestamps trail the wall clock, and a freshly created node
	// ranks newest (it just arrived) so it is never evicted before its first
	// edge lands.
	nodeLastSeen map[string]uint64

	// touchSeq is the graph-global monotonic counter backing nodeLastSeen.
	touchSeq uint64

	// maxNodes, when > 0, bounds the live node count. Once exceeded after an
	// insert, the least-recently-touched nodes (by nodeLastSeen) and their
	// incident edges are evicted until the count is back at or below the bound.
	// Zero means unbounded, the default, which preserves the original behavior.
	maxNodes int

	// onEvict, when set, is invoked after each eviction pass with the IDs of
	// the nodes and edges that were removed. Downstream state owners (e.g. the
	// scorer's per-node and per-edge maps) register here to prune in step with
	// the graph. Invoked while holding the graph write lock; the callback must
	// not call back into the graph.
	onEvict func(nodeIDs, edgeIDs []string)
}

// New returns an empty graph ready for streaming inserts.
func New() *Graph {
	return &Graph{
		nodes:        make(map[string]*types.Node),
		edges:        make(map[string]*types.Edge),
		outEdges:     make(map[string][]*types.Edge),
		inEdges:      make(map[string][]*types.Edge),
		nodeLastSeen: make(map[string]uint64),
		createdAt:    time.Now().UTC(),
	}
}

// SetMaxNodes configures an optional retention bound on the live node count.
// A value of n > 0 caps the graph at n nodes: after any insert pushes the count
// past n, the least-recently-touched nodes and all their incident edges are
// evicted until the count is back within the bound. A value of 0 (the
// default) disables eviction and preserves the original unbounded behavior.
// Additive: existing callers that never call this see no change.
func (g *Graph) SetMaxNodes(n int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.maxNodes = n
	g.evictLocked()
}

// SetEvictionCallback registers fn to be notified after each eviction pass with
// the node and edge IDs that were removed. It is invoked under the graph write
// lock; fn must not call back into the graph. Passing nil clears the callback.
// Additive: with no callback registered (the default), eviction simply drops
// the entries from the graph's own maps.
func (g *Graph) SetEvictionCallback(fn func(nodeIDs, edgeIDs []string)) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.onEvict = fn
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
	// A freshly created node is the most recently touched thing in the graph,
	// so it ranks newest and is never evicted before its first edge lands.
	g.touchLocked(id)
	g.evictLocked()
	return n
}

// AppendEdge inserts a new edge and updates both adjacency lists. Returns the
// stored *types.Edge so the caller can refer to it by ID later (e.g. scorer
// emits score_update messages keyed on edge.ID).
func (g *Graph) AppendEdge(src, dst *types.Node, kind types.EdgeKind, ts time.Time, confidence float64, srcEventID string) *types.Edge {
	g.mu.Lock()
	defer g.mu.Unlock()
	// Re-materialize either endpoint if it was evicted between the caller's
	// FindOrCreateNode and this AppendEdge. Under the documented single-writer
	// contract this never fires, but with the retention bound active a second
	// goroutine could evict a node a caller is still holding a pointer to; left
	// unhandled that would seat an edge whose endpoint is absent from g.nodes,
	// surfacing a dangling edge through Snapshot and the adjacency reads. The
	// node pointer carries everything needed to restore it.
	g.relinkLocked(src)
	g.relinkLocked(dst)
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
	// Touch both endpoints so least-recently-touched ordering reflects recent
	// activity, not just node creation order.
	g.touchLocked(src.ID)
	g.touchLocked(dst.ID)
	g.evictLocked()
	return e
}

// relinkLocked re-inserts n into the node map if it is missing (i.e. it was
// evicted while a caller still held its pointer). It is a no-op when n is
// already live, so the common path costs only a map lookup. Caller must hold
// g.mu for writing.
func (g *Graph) relinkLocked(n *types.Node) {
	if _, ok := g.nodes[n.ID]; !ok {
		g.nodes[n.ID] = n
	}
}

// touchLocked advances the global logical clock and stamps it on nodeID,
// marking the node most-recently-touched. Caller must hold g.mu for writing.
func (g *Graph) touchLocked(nodeID string) {
	g.touchSeq++
	g.nodeLastSeen[nodeID] = g.touchSeq
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

// SetEdgeConfidence records the scorer's verdict on an edge under the graph
// lock so concurrent readers (chain extraction, snapshots) never observe a
// torn or racing write.
func (g *Graph) SetEdgeConfidence(edgeID string, score float64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if e, ok := g.edges[edgeID]; ok {
		e.Confidence = score
	}
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

// evictLocked enforces the maxNodes retention bound. It removes the
// least-recently-touched nodes, together with every edge incident to a removed
// node, until the live node count is at or below the bound. A non-positive
// bound is a no-op, so the default (unbounded) graph behaves exactly as before.
// Caller must hold g.mu for writing.
func (g *Graph) evictLocked() {
	if g.maxNodes <= 0 || len(g.nodes) <= g.maxNodes {
		return
	}

	// Order node IDs least-recently-touched first by logical touch sequence.
	// Each node has a distinct sequence (every create and edge-touch bumps the
	// global counter), so the ordering is total and deterministic; the ID
	// tie-break is a belt-and-suspenders guard that never actually fires.
	ids := make([]string, 0, len(g.nodes))
	for id := range g.nodes {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		ti, tj := g.nodeLastSeen[ids[i]], g.nodeLastSeen[ids[j]]
		if ti != tj {
			return ti < tj
		}
		return ids[i] < ids[j]
	})

	overflow := len(g.nodes) - g.maxNodes
	victims := ids[:overflow]

	evictedNodes := make([]string, 0, overflow)
	evictedEdges := make([]string, 0, overflow)
	victimSet := make(map[string]bool, overflow)
	for _, id := range victims {
		victimSet[id] = true
	}

	for _, id := range victims {
		// Collect every edge touching this node from both adjacency lists.
		for _, e := range g.outEdges[id] {
			if _, ok := g.edges[e.ID]; ok {
				evictedEdges = append(evictedEdges, e.ID)
				delete(g.edges, e.ID)
			}
		}
		for _, e := range g.inEdges[id] {
			if _, ok := g.edges[e.ID]; ok {
				evictedEdges = append(evictedEdges, e.ID)
				delete(g.edges, e.ID)
			}
		}
		delete(g.outEdges, id)
		delete(g.inEdges, id)
		delete(g.nodes, id)
		delete(g.nodeLastSeen, id)
		evictedNodes = append(evictedNodes, id)
	}

	// Surviving nodes may still hold adjacency entries pointing at evicted
	// edges (e.g. an edge between a survivor and a victim). Compact those
	// lists so EdgeCount-consistent reads never surface a deleted edge.
	g.compactAdjacencyLocked(victimSet)

	if g.onEvict != nil && (len(evictedNodes) > 0 || len(evictedEdges) > 0) {
		g.onEvict(evictedNodes, evictedEdges)
	}
}

// compactAdjacencyLocked drops, from every surviving node's in/out edge lists,
// any edge whose endpoint was evicted (and is therefore no longer in g.edges).
// Caller must hold g.mu for writing.
func (g *Graph) compactAdjacencyLocked(victimSet map[string]bool) {
	prune := func(lists map[string][]*types.Edge) {
		for nid, es := range lists {
			kept := es[:0]
			for _, e := range es {
				if _, ok := g.edges[e.ID]; ok {
					kept = append(kept, e)
				}
			}
			if len(kept) == 0 {
				delete(lists, nid)
			} else {
				lists[nid] = kept
			}
		}
	}
	prune(g.outEdges)
	prune(g.inEdges)
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
