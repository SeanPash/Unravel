package chain

import (
	"math"
	"testing"
	"time"

	"github.com/luigifernandez/unravel/engine/internal/graph"
	"github.com/luigifernandez/unravel/engine/internal/types"
)

// Extract walks backward from the hot node through the highest-scored incoming
// edge at each step, and returns the steps in chronological (forward) order.
func TestExtract_BackwardWalkReturnsStepsInChronologicalOrder(t *testing.T) {
	g := graph.New()

	cmd := g.FindOrCreateNode(types.NodeKindProcess, "p-cmd", "cmd.exe", nil)
	ps := g.FindOrCreateNode(types.NodeKindProcess, "p-ps", "powershell.exe", nil)
	lsass := g.FindOrCreateNode(types.NodeKindProcess, "p-lsass", "lsass.exe", nil)

	e1 := g.AppendEdge(cmd, ps, types.EdgeKindSpawned, time.Unix(1000, 0).UTC(), 0.9, "evt-1")
	e2 := g.AppendEdge(ps, lsass, types.EdgeKindAccessedCredential, time.Unix(1010, 0).UTC(), 0.85, "evt-2")

	scores := map[string]float64{e1.ID: 0.8, e2.ID: 0.95}
	scoreFn := func(edgeID string) float64 { return scores[edgeID] }

	result := Extract(g, scoreFn, lsass.ID)

	if len(result.Steps) != 2 {
		t.Fatalf("got %d steps, want 2", len(result.Steps))
	}
	if result.Steps[0].EventID != "evt-1" {
		t.Errorf("step[0].EventID = %q, want evt-1", result.Steps[0].EventID)
	}
	if result.Steps[1].EventID != "evt-2" {
		t.Errorf("step[1].EventID = %q, want evt-2", result.Steps[1].EventID)
	}
	if result.Steps[0].TS != 1000 || result.Steps[1].TS != 1010 {
		t.Errorf("step timestamps = %d, %d; want 1000, 1010", result.Steps[0].TS, result.Steps[1].TS)
	}
}

// At each backward step, the walker picks the incoming edge with the highest
// score, not the most recent timestamp.
func TestExtract_PicksHighestScoredIncomingEdge(t *testing.T) {
	g := graph.New()

	noisyParent := g.FindOrCreateNode(types.NodeKindProcess, "p-noisy", "explorer.exe", nil)
	badParent := g.FindOrCreateNode(types.NodeKindProcess, "p-bad", "wscript.exe", nil)
	child := g.FindOrCreateNode(types.NodeKindProcess, "p-child", "powershell.exe", nil)

	noisyEdge := g.AppendEdge(noisyParent, child, types.EdgeKindSpawned, time.Unix(2000, 0).UTC(), 0.5, "evt-noisy")
	badEdge := g.AppendEdge(badParent, child, types.EdgeKindSpawned, time.Unix(1000, 0).UTC(), 0.9, "evt-bad")

	scores := map[string]float64{noisyEdge.ID: 0.1, badEdge.ID: 0.95}
	scoreFn := func(edgeID string) float64 { return scores[edgeID] }

	result := Extract(g, scoreFn, child.ID)

	if len(result.Steps) != 1 {
		t.Fatalf("got %d steps, want 1", len(result.Steps))
	}
	if result.Steps[0].EventID != "evt-bad" {
		t.Errorf("step[0].EventID = %q, want evt-bad (higher score)", result.Steps[0].EventID)
	}
}

// Chain confidence is the geometric mean of per-step confidences. A step's
// confidence is the value the passed scoreFn returns for its edge, not the
// edge's stored Confidence field: chain extraction reads scores through the
// scorer's mutex-guarded accessor to stay race-free with ingest. The stored
// AppendEdge confidences below are therefore deliberately irrelevant.
func TestExtract_ConfidenceIsGeometricMeanOfSteps(t *testing.T) {
	g := graph.New()

	a := g.FindOrCreateNode(types.NodeKindProcess, "a", "a", nil)
	b := g.FindOrCreateNode(types.NodeKindProcess, "b", "b", nil)
	c := g.FindOrCreateNode(types.NodeKindProcess, "c", "c", nil)

	e1 := g.AppendEdge(a, b, types.EdgeKindSpawned, time.Unix(100, 0).UTC(), 0, "evt-1")
	e2 := g.AppendEdge(b, c, types.EdgeKindSpawned, time.Unix(200, 0).UTC(), 0, "evt-2")

	scores := map[string]float64{e1.ID: 0.81, e2.ID: 0.64}
	scoreFn := func(edgeID string) float64 { return scores[edgeID] }

	result := Extract(g, scoreFn, c.ID)
	want := math.Sqrt(0.81 * 0.64)
	if math.Abs(result.Confidence-want) > 1e-9 {
		t.Errorf("confidence = %f, want %f", result.Confidence, want)
	}
}

// The walker stops at the first node with no incoming edges; it does not loop
// forever when a cycle exists in the graph.
func TestExtract_StopsOnCycle(t *testing.T) {
	g := graph.New()

	a := g.FindOrCreateNode(types.NodeKindProcess, "a", "a", nil)
	b := g.FindOrCreateNode(types.NodeKindProcess, "b", "b", nil)

	e1 := g.AppendEdge(a, b, types.EdgeKindSpawned, time.Unix(100, 0).UTC(), 0.9, "evt-1")
	e2 := g.AppendEdge(b, a, types.EdgeKindSpawned, time.Unix(200, 0).UTC(), 0.9, "evt-2")

	scores := map[string]float64{e1.ID: 1, e2.ID: 1}
	scoreFn := func(edgeID string) float64 { return scores[edgeID] }

	done := make(chan struct{})
	go func() {
		Extract(g, scoreFn, b.ID)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Extract did not terminate on cyclic graph")
	}
}

// A step description should be a short human-readable phrase mentioning both
// endpoints and the edge kind.
func TestExtract_StepDescriptionMentionsEndpointsAndKind(t *testing.T) {
	g := graph.New()

	cmd := g.FindOrCreateNode(types.NodeKindProcess, "p-cmd", "cmd.exe", nil)
	ps := g.FindOrCreateNode(types.NodeKindProcess, "p-ps", "powershell.exe", nil)

	e := g.AppendEdge(cmd, ps, types.EdgeKindSpawned, time.Unix(100, 0).UTC(), 0.9, "evt-1")
	scoreFn := func(string) float64 { return 1 }

	result := Extract(g, scoreFn, ps.ID)

	if len(result.Steps) != 1 {
		t.Fatalf("got %d steps, want 1", len(result.Steps))
	}
	desc := result.Steps[0].Description
	for _, want := range []string{"cmd.exe", "powershell.exe", "spawned"} {
		if !contains(desc, want) {
			t.Errorf("description %q missing %q", desc, want)
		}
	}
	_ = e
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// nodeRegistry maps a short test-local ID to the node returned by
// FindOrCreateNode. This bridges the plan's addNode/addEdge helper API (which
// use caller-chosen short IDs) with graph.Graph's internal "proc-<key>" IDs.
type nodeRegistry map[string]*types.Node

func addNode(t *testing.T, g *graph.Graph, reg nodeRegistry, id string, kind types.NodeKind, label string) {
	t.Helper()
	reg[id] = g.FindOrCreateNode(kind, id, label, nil)
}

func addEdge(t *testing.T, g *graph.Graph, reg nodeRegistry, eventID, srcID, dstID string, kind types.EdgeKind, ts int64, conf float64) {
	t.Helper()
	g.AppendEdge(reg[srcID], reg[dstID], kind, time.Unix(ts, 0).UTC(), conf, eventID)
}

func TestExtractAnnotatesTechniquesAndTactics(t *testing.T) {
	g := graph.New()
	reg := nodeRegistry{}
	// Build: winword --spawned--> powershell --dumped_memory_of--> lsass
	addNode(t, g, reg, "p-word", types.NodeKindProcess, "WINWORD.EXE")
	addNode(t, g, reg, "p-ps", types.NodeKindProcess, "powershell.exe")
	addNode(t, g, reg, "p-lsass", types.NodeKindProcess, "lsass.exe")
	addEdge(t, g, reg, "e1", "p-word", "p-ps", types.EdgeKindSpawned, 1, 0.7)
	addEdge(t, g, reg, "e2", "p-ps", "p-lsass", types.EdgeKindDumpedMemoryOf, 2, 0.9)

	score := func(id string) float64 { return 1.0 }
	result := Extract(g, score, reg["p-lsass"].ID)

	if len(result.Steps) != 2 {
		t.Fatalf("steps = %d, want 2", len(result.Steps))
	}
	if result.Steps[0].TechniqueID != "T1566.001" {
		t.Errorf("step0 technique = %q, want T1566.001", result.Steps[0].TechniqueID)
	}
	if result.Steps[1].TechniqueID != "T1003.001" {
		t.Errorf("step1 technique = %q, want T1003.001", result.Steps[1].TechniqueID)
	}
	wantTactics := []string{"Initial Access", "Credential Access"}
	if len(result.Tactics) != 2 || result.Tactics[0] != wantTactics[0] || result.Tactics[1] != wantTactics[1] {
		t.Errorf("tactics = %v, want %v", result.Tactics, wantTactics)
	}
}
