package graph

import (
	"sync"
	"testing"
	"time"

	"github.com/luigifernandez/unravel/engine/internal/types"
)

func TestFindOrCreateNode_Idempotent(t *testing.T) {
	g := New()
	a := g.FindOrCreateNode(types.NodeKindProcess, "WS01-1234", "powershell.exe", map[string]any{"pid": 1234})
	b := g.FindOrCreateNode(types.NodeKindProcess, "WS01-1234", "ignored-label", map[string]any{"pid": 9999})

	if a != b {
		t.Fatalf("second FindOrCreateNode returned a different pointer: %p vs %p", a, b)
	}
	if a.Label != "powershell.exe" {
		t.Errorf("Label changed on repeat call: %q", a.Label)
	}
	if a.Attrs["pid"].(int) != 1234 {
		t.Errorf("Attrs overwritten on repeat call: %v", a.Attrs)
	}
	if g.NodeCount() != 1 {
		t.Errorf("NodeCount = %d, want 1", g.NodeCount())
	}
}

func TestFindOrCreateNode_DifferentKindsAreDistinct(t *testing.T) {
	g := New()
	p := g.FindOrCreateNode(types.NodeKindProcess, "x", "p", nil)
	h := g.FindOrCreateNode(types.NodeKindHost, "x", "h", nil)
	if p.ID == h.ID {
		t.Errorf("Process and Host with same key collided on ID %q", p.ID)
	}
	if g.NodeCount() != 2 {
		t.Errorf("NodeCount = %d, want 2", g.NodeCount())
	}
}

func TestNodeID_UsesKindPrefix(t *testing.T) {
	if got := NodeID(types.NodeKindProcess, "WS01-1234"); got != "proc-WS01-1234" {
		t.Errorf("NodeID(Process, WS01-1234) = %q, want proc-WS01-1234", got)
	}
	if got := NodeID(types.NodeKindHost, "DC01"); got != "host-DC01" {
		t.Errorf("NodeID(Host, DC01) = %q, want host-DC01", got)
	}
}

func TestAppendEdge_UpdatesAdjacency(t *testing.T) {
	g := New()
	parent := g.FindOrCreateNode(types.NodeKindProcess, "WS01-100", "cmd.exe", nil)
	child := g.FindOrCreateNode(types.NodeKindProcess, "WS01-200", "powershell.exe", nil)

	ts := time.Date(2026, 6, 5, 19, 30, 0, 0, time.UTC)
	e := g.AppendEdge(parent, child, types.EdgeKindSpawned, ts, 0.8, "evt-001")

	if e.ID == "" {
		t.Fatal("AppendEdge returned edge with empty ID")
	}
	if e.Src != parent.ID || e.Dst != child.ID {
		t.Errorf("edge endpoints wrong: %s -> %s, want %s -> %s", e.Src, e.Dst, parent.ID, child.ID)
	}
	if e.Kind != types.EdgeKindSpawned {
		t.Errorf("Kind = %q, want spawned", e.Kind)
	}
	if e.TS != ts.Unix() {
		t.Errorf("TS = %d, want %d", e.TS, ts.Unix())
	}
	if e.Confidence != 0.8 {
		t.Errorf("Confidence = %f, want 0.8", e.Confidence)
	}
	if e.SourceEventID != "evt-001" {
		t.Errorf("SourceEventID = %q, want evt-001", e.SourceEventID)
	}

	out := g.OutEdges(parent.ID)
	if len(out) != 1 || out[0].ID != e.ID {
		t.Errorf("OutEdges(parent) = %+v, want one edge %q", out, e.ID)
	}
	in := g.InEdges(child.ID)
	if len(in) != 1 || in[0].ID != e.ID {
		t.Errorf("InEdges(child) = %+v, want one edge %q", in, e.ID)
	}
	if g.EdgeCount() != 1 {
		t.Errorf("EdgeCount = %d, want 1", g.EdgeCount())
	}
}

func TestAppendEdge_UniqueIDsAndLookup(t *testing.T) {
	g := New()
	a := g.FindOrCreateNode(types.NodeKindProcess, "a", "a", nil)
	b := g.FindOrCreateNode(types.NodeKindProcess, "b", "b", nil)
	c := g.FindOrCreateNode(types.NodeKindProcess, "c", "c", nil)

	ts := time.Now().UTC()
	e1 := g.AppendEdge(a, b, types.EdgeKindSpawned, ts, 0.5, "evt-1")
	e2 := g.AppendEdge(b, c, types.EdgeKindSpawned, ts, 0.6, "evt-2")
	e3 := g.AppendEdge(a, c, types.EdgeKindSpawned, ts, 0.7, "evt-3")

	if e1.ID == e2.ID || e2.ID == e3.ID || e1.ID == e3.ID {
		t.Errorf("duplicate edge IDs: %s %s %s", e1.ID, e2.ID, e3.ID)
	}
	if g.Edge(e2.ID) != e2 {
		t.Errorf("Edge(%q) lookup mismatch", e2.ID)
	}
	if g.Node(a.ID) != a {
		t.Errorf("Node(%q) lookup mismatch", a.ID)
	}

	outA := g.OutEdges(a.ID)
	if len(outA) != 2 {
		t.Errorf("OutEdges(a) has %d edges, want 2", len(outA))
	}
	inC := g.InEdges(c.ID)
	if len(inC) != 2 {
		t.Errorf("InEdges(c) has %d edges, want 2", len(inC))
	}
}

func TestSnapshot_DeepCopiesNodes(t *testing.T) {
	g := New()
	parent := g.FindOrCreateNode(types.NodeKindProcess, "p", "cmd.exe", map[string]any{"pid": 1})
	child := g.FindOrCreateNode(types.NodeKindProcess, "c", "powershell.exe", map[string]any{"pid": 2})
	g.AppendEdge(parent, child, types.EdgeKindSpawned, time.Now().UTC(), 0.5, "evt-1")

	snap := g.Snapshot()
	if len(snap.Nodes) != 2 {
		t.Fatalf("Snapshot Nodes len = %d, want 2", len(snap.Nodes))
	}
	if len(snap.Edges) != 1 {
		t.Fatalf("Snapshot Edges len = %d, want 1", len(snap.Edges))
	}

	// Mutating snapshot attrs must not affect graph state.
	for i := range snap.Nodes {
		if snap.Nodes[i].ID == parent.ID {
			snap.Nodes[i].Attrs["pid"] = 9999
		}
	}
	if parent.Attrs["pid"].(int) != 1 {
		t.Errorf("Snapshot did not deep-copy node attrs; parent.Attrs[pid] = %v", parent.Attrs["pid"])
	}
}

func TestInEdges_AbsentNodeReturnsNil(t *testing.T) {
	g := New()
	if got := g.InEdges("nope"); got != nil {
		t.Errorf("InEdges on absent node = %+v, want nil", got)
	}
	if got := g.OutEdges("nope"); got != nil {
		t.Errorf("OutEdges on absent node = %+v, want nil", got)
	}
}

func TestConcurrentReadersDuringWrites(t *testing.T) {
	g := New()
	// Pre-create some structure so readers have something to observe.
	for i := 0; i < 10; i++ {
		g.FindOrCreateNode(types.NodeKindProcess, string(rune('a'+i)), "x", nil)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = g.Snapshot()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			n := g.FindOrCreateNode(types.NodeKindProcess, "writer", "x", nil)
			g.AppendEdge(n, n, types.EdgeKindSpawned, time.Now().UTC(), 0.1, "evt")
		}
	}()
	wg.Wait()
	if g.NodeCount() < 10 {
		t.Errorf("NodeCount = %d after concurrent run", g.NodeCount())
	}
}
