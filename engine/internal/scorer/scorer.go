// Package scorer implements the engine's online suspicion scorer. Phase 1 uses
// frequency-rarity only: how unusual is this (parent, child) image tuple?
// When the mean score of any connected subgraph crosses the configured
// threshold, the scorer emits a Signal so the chain extractor can run.
package scorer

import (
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/luigifernandez/unravel/engine/internal/graph"
	"github.com/luigifernandez/unravel/engine/internal/types"
)

// Config tunes the scorer's three signals and the trigger threshold. Zero
// values get sensible defaults applied in New so callers can supply a partial
// Config.
type Config struct {
	Threshold       float64
	HalfLife        time.Duration
	SensitiveLabels []string
	LiftFactor      float64
	SignalBuffer    int
}

// Signal is emitted on the Signals channel when a component's mean edge score
// crosses Config.Threshold. HotNode is the destination of the highest-scoring
// edge in the component, intended as the chain extractor's starting point.
// IncidentID is a stable identifier for the connected component; it is minted
// on the first signal from a component and preserved across subsequent growth
// or merges.
type Signal struct {
	HotNode    string
	Mean       float64
	IncidentID string
}

// Scorer holds the incremental state needed to score each new edge in O(1)
// plus a component walk. Safe for concurrent ScoreEdge calls from the pipeline
// goroutine; the public methods serialize on a single mutex.
type Scorer struct {
	mu  sync.Mutex
	cfg Config

	spawnCounts map[string]int
	authCounts  map[string]int
	nodeLastTS  map[string]int64
	edgeScores  map[string]float64
	authKinds   map[string]string

	nodeIncident map[string]string // node id -> stable incident id
	incidentSeq  int               // monotonic counter for minting ids

	signals chan Signal
}

// New returns a Scorer with the supplied config; zero-valued fields receive
// defaults so a caller can pass `Config{}` for a basic instance.
func New(cfg Config) *Scorer {
	if cfg.HalfLife <= 0 {
		cfg.HalfLife = 30 * time.Second
	}
	if cfg.LiftFactor <= 0 {
		cfg.LiftFactor = 2.0
	}
	if cfg.SignalBuffer <= 0 {
		cfg.SignalBuffer = 64
	}
	if cfg.Threshold == 0 {
		cfg.Threshold = math.Inf(1)
	}
	return &Scorer{
		cfg:          cfg,
		spawnCounts:  make(map[string]int),
		authCounts:   make(map[string]int),
		nodeLastTS:   make(map[string]int64),
		edgeScores:   make(map[string]float64),
		authKinds:    make(map[string]string),
		nodeIncident: make(map[string]string),
		signals:      make(chan Signal, cfg.SignalBuffer),
	}
}

// Signals returns the receive end of the threshold-trigger channel. The
// channel is buffered; the scorer drops signals rather than blocking the
// pipeline if a consumer falls behind.
func (s *Scorer) Signals() <-chan Signal { return s.signals }

// PruneNodes drops all per-node state for the given node IDs. Call it in step
// with graph eviction (e.g. from the graph's eviction callback) so the scorer's
// node-keyed maps do not grow without bound in long-running streaming sessions.
// The tuple-keyed frequency baselines (spawnCounts, authCounts) are deliberately
// left intact: they model how common a (parent,child) image pair is across the
// whole stream, not per-node state, so pruning them would discard learned rarity.
// Additive and concurrency-safe: serializes on the scorer mutex.
func (s *Scorer) PruneNodes(nodeIDs []string) {
	if len(nodeIDs) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range nodeIDs {
		delete(s.nodeLastTS, id)
		delete(s.nodeIncident, id)
	}
}

// PruneEdges drops all per-edge state for the given edge IDs. Call it in step
// with graph eviction so the scorer's edge-keyed maps stay bounded. Additive and
// concurrency-safe: serializes on the scorer mutex.
func (s *Scorer) PruneEdges(edgeIDs []string) {
	if len(edgeIDs) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range edgeIDs {
		delete(s.edgeScores, id)
		delete(s.authKinds, id)
	}
}

// SetAuthKind tags an authentication edge with its protocol (e.g. "kerberos",
// "ntlm") so the frequency-rarity term can use a role/kind tuple. The pipeline
// calls this from the schema mapper before ScoreEdge.
func (s *Scorer) SetAuthKind(e *types.Edge, kind string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authKinds[e.ID] = kind
}

// ScoreEdge computes the frequency-rarity score for e (Phase 1), updates
// internal state, and emits a Signal if the resulting component mean crosses
// Threshold.
func (s *Scorer) ScoreEdge(e *types.Edge, g *graph.Graph) float64 {
	s.observeTouch(e)
	score := s.freqRarity(e, g)

	s.mu.Lock()
	s.edgeScores[e.ID] = score
	s.mu.Unlock()

	mean, hot, incident := s.componentMean(e, g)
	if mean > s.cfg.Threshold {
		select {
		case s.signals <- Signal{HotNode: hot, Mean: mean, IncidentID: incident}:
		default:
		}
	}
	return score
}

// EdgeScore returns the scorer's recorded suspicion score for an edge, reading
// the edgeScores map under the scorer mutex. Chain extraction uses this as its
// ScoreFn so the backward walk never races the ingest goroutine's writes to
// edge.Confidence; an unscored edge reads as 0.
func (s *Scorer) EdgeScore(edgeID string) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.edgeScores[edgeID]
}

// freqRarity is the unigram term. The (parent_image, child_image) tuple for
// spawn edges and the (src_role, dst_role, auth_kind) tuple for auth edges are
// counted; the score is 1 / log(1 + count_after_increment) so the first
// observation scores highest and identical repeats decay sub-linearly.
func (s *Scorer) freqRarity(e *types.Edge, g *graph.Graph) float64 {
	key, m := s.freqKey(e, g)
	s.mu.Lock()
	m[key]++
	n := m[key]
	s.mu.Unlock()
	return 1.0 / math.Log(1.0+float64(n))
}

// freqKey returns the bucket key and the matching count map for e.
func (s *Scorer) freqKey(e *types.Edge, g *graph.Graph) (string, map[string]int) {
	src, dst := g.Node(e.Src), g.Node(e.Dst)
	if e.Kind == types.EdgeKindAuthenticatedAs {
		s.mu.Lock()
		kind := s.authKinds[e.ID]
		s.mu.Unlock()
		return roleAttr(src) + "|" + roleAttr(dst) + "|" + kind, s.authCounts
	}
	return labelOf(src) + "|" + labelOf(dst), s.spawnCounts
}

// temporalDecay applies an exponential half-life decay to the score based on
// how long ago either endpoint was last touched. The first edge to ever touch
// either endpoint gets factor 1.0; subsequent edges decay by 0.5 per half-life
// of elapsed time. Out-of-order arrivals reset to 1.0.
func (s *Scorer) temporalDecay(e *types.Edge) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	lastSrc, hasSrc := s.nodeLastTS[e.Src]
	lastDst, hasDst := s.nodeLastTS[e.Dst]
	if !hasSrc && !hasDst {
		return 1.0
	}
	var last int64
	switch {
	case hasSrc && hasDst:
		if lastSrc > lastDst {
			last = lastSrc
		} else {
			last = lastDst
		}
	case hasSrc:
		last = lastSrc
	default:
		last = lastDst
	}
	gap := e.TS - last
	if gap <= 0 {
		return 1.0
	}
	return math.Pow(0.5, float64(gap)/s.cfg.HalfLife.Seconds())
}

func (s *Scorer) observeTouch(e *types.Edge) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.TS > s.nodeLastTS[e.Src] {
		s.nodeLastTS[e.Src] = e.TS
	}
	if e.TS > s.nodeLastTS[e.Dst] {
		s.nodeLastTS[e.Dst] = e.TS
	}
}

// structuralLift returns LiftFactor when e touches a sensitive node or crosses
// a host boundary, else 1.0. Sensitive nodes are matched by exact label; the
// host boundary check requires both endpoints to carry a "host" attr.
func (s *Scorer) structuralLift(e *types.Edge, g *graph.Graph) float64 {
	src, dst := g.Node(e.Src), g.Node(e.Dst)
	if s.isSensitive(src) || s.isSensitive(dst) {
		return s.cfg.LiftFactor
	}
	if crossHost(src, dst) {
		return s.cfg.LiftFactor
	}
	return 1.0
}

func (s *Scorer) isSensitive(n *types.Node) bool {
	if n == nil {
		return false
	}
	for _, l := range s.cfg.SensitiveLabels {
		if n.Label == l {
			return true
		}
	}
	return false
}

func crossHost(src, dst *types.Node) bool {
	if src == nil || dst == nil {
		return false
	}
	sh, sok := src.Attrs["host"].(string)
	dh, dok := dst.Attrs["host"].(string)
	if !sok || !dok {
		return false
	}
	return sh != dh
}

// componentMean returns the mean of the latest scores recorded for edges in
// the connected component containing both endpoints of e, plus the hottest
// node in that component (destination of the highest-scoring edge).
func (s *Scorer) componentMean(start *types.Edge, g *graph.Graph) (float64, string, string) {
	seenNodes := make(map[string]bool)
	seenEdges := make(map[string]bool)
	queue := []string{start.Src, start.Dst}

	// edgeTS / edgeDst capture each component edge's timestamp and destination
	// during the BFS. All graph reads MUST happen here, while no scorer lock is
	// held: the eviction callback runs under the graph write lock and then takes
	// the scorer lock, so taking a graph lock while holding the scorer lock would
	// invert that order and deadlock (ABBA). We therefore snapshot everything the
	// locked aggregation needs up front and never touch the graph under s.mu.
	edgeTS := make(map[string]int64)
	edgeDst := make(map[string]string)

	for len(queue) > 0 {
		nid := queue[0]
		queue = queue[1:]
		if seenNodes[nid] {
			continue
		}
		seenNodes[nid] = true
		for _, e := range g.OutEdges(nid) {
			if !seenEdges[e.ID] {
				seenEdges[e.ID] = true
				edgeTS[e.ID] = e.TS
				edgeDst[e.ID] = e.Dst
				queue = append(queue, e.Dst)
			}
		}
		for _, e := range g.InEdges(nid) {
			if !seenEdges[e.ID] {
				seenEdges[e.ID] = true
				edgeTS[e.ID] = e.TS
				edgeDst[e.ID] = e.Dst
				queue = append(queue, e.Src)
			}
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	incident := s.resolveIncident(seenNodes)
	var sum float64
	var count int
	var hotEdge string
	var hotTS int64
	for eid := range seenEdges {
		sc, ok := s.edgeScores[eid]
		if !ok {
			continue
		}
		sum += sc
		count++
		// Hot node is the destination of the freshest edge in the component:
		// the chain extractor walks backward from there, so picking the tip of
		// the suspicious chain (rather than its root) gives the full kill
		// chain. The mean-vs-threshold check above already gates "is this
		// component suspicious?"; the hot-edge selection just picks the right
		// starting point for the backward walk. Timestamps come from the BFS
		// snapshot, not a fresh graph read, to keep the lock order graph-then-
		// scorer everywhere (see the note above).
		ts := edgeTS[eid]
		if ts > hotTS || hotEdge == "" {
			hotEdge = eid
			hotTS = ts
		}
	}
	if count == 0 {
		return 0, start.Dst, incident
	}
	hotNode := start.Dst
	if hotEdge != "" {
		if dst, ok := edgeDst[hotEdge]; ok {
			hotNode = dst
		}
	}
	return sum / float64(count), hotNode, incident
}

// resolveIncident assigns or reuses a stable incident id for a component's
// members. A fresh component mints a new id; a component that already holds one
// or more incidents reuses the earliest and absorbs the rest (a merge). Every
// member is then (re)mapped to the chosen id. Caller must hold s.mu.
func (s *Scorer) resolveIncident(members map[string]bool) string {
	existing := make(map[string]bool)
	for nid := range members {
		if id, ok := s.nodeIncident[nid]; ok {
			existing[id] = true
		}
	}
	var chosen string
	if len(existing) == 0 {
		chosen = "inc-" + strconv.Itoa(s.incidentSeq)
		s.incidentSeq++
	} else {
		chosen = earliestIncident(existing)
	}
	for nid := range members {
		s.nodeIncident[nid] = chosen
	}
	return chosen
}

// earliestIncident returns the id with the smallest numeric suffix. Ids are
// minted as "inc-<n>"; the lowest n is the earliest incident, which a merge
// absorbs the others into.
func earliestIncident(ids map[string]bool) string {
	best := ""
	bestN := 1 << 30
	for id := range ids {
		n := incidentNum(id)
		if best == "" || n < bestN {
			best, bestN = id, n
		}
	}
	return best
}

// incidentNum parses the numeric suffix of an "inc-<n>" id. A malformed id maps
// to a large number so it never wins the earliest comparison.
func incidentNum(id string) int {
	n, err := strconv.Atoi(strings.TrimPrefix(id, "inc-"))
	if err != nil {
		return 1 << 30
	}
	return n
}

func labelOf(n *types.Node) string {
	if n == nil {
		return ""
	}
	return n.Label
}

func roleAttr(n *types.Node) string {
	if n == nil {
		return ""
	}
	if r, ok := n.Attrs["role"].(string); ok {
		return r
	}
	return ""
}
