package scorer

import (
	"math"
	"testing"
	"time"

	"github.com/luigifernandez/unravel/engine/internal/graph"
	"github.com/luigifernandez/unravel/engine/internal/types"
)

// freqRarity is monotonic-decreasing in count: first occurrence of a (parent_image,
// child_image) pair must score strictly higher than the second, and the second
// strictly higher than the third.
func TestFreqRarity_RareTuplesScoreHigherThanCommonOnes(t *testing.T) {
	s := New(Config{})
	g := graph.New()

	score := func(parentLabel, childLabel, srcKey, dstKey, evtID string) float64 {
		p := g.FindOrCreateNode(types.NodeKindProcess, srcKey, parentLabel, nil)
		c := g.FindOrCreateNode(types.NodeKindProcess, dstKey, childLabel, nil)
		e := g.AppendEdge(p, c, types.EdgeKindSpawned, time.Unix(0, 0).UTC(), 1, evtID)
		return s.freqRarity(e, g)
	}

	first := score("cmd.exe", "powershell.exe", "p1", "c1", "evt-1")
	second := score("cmd.exe", "powershell.exe", "p2", "c2", "evt-2")
	third := score("cmd.exe", "powershell.exe", "p3", "c3", "evt-3")

	if !(first > second && second > third) {
		t.Errorf("expected strictly decreasing: %f > %f > %f", first, second, third)
	}

	// A new tuple should re-score as high as the original first observation.
	novel := score("explorer.exe", "calc.exe", "p4", "c4", "evt-4")
	if novel < first-1e-9 || novel > first+1e-9 {
		t.Errorf("novel tuple score = %f, want ~%f (same as first observation)", novel, first)
	}
}

// Authentication edges use a different tuple key (src/dst role + auth kind)
// extracted from edge endpoint attrs.
func TestFreqRarity_AuthEdgesUseRoleTuple(t *testing.T) {
	s := New(Config{})
	g := graph.New()

	src := g.FindOrCreateNode(types.NodeKindUser, "alice", "alice", map[string]any{"role": "user"})
	dst := g.FindOrCreateNode(types.NodeKindHost, "DC01", "DC01", map[string]any{"role": "dc"})
	e1 := g.AppendEdge(src, dst, types.EdgeKindAuthenticatedAs, time.Unix(0, 0).UTC(), 1, "evt-1")
	e1.Kind = types.EdgeKindAuthenticatedAs
	// Mark auth kind via edge confidence-adjacent metadata: use a known attrs map on
	// the destination node since edges do not carry attrs. (Mirrors how the
	// schema mapper records Kerberos vs. NTLM via the resource node.)
	s.SetAuthKind(e1, "kerberos")
	score1 := s.freqRarity(e1, g)

	src2 := g.FindOrCreateNode(types.NodeKindUser, "alice2", "alice", map[string]any{"role": "user"})
	dst2 := g.FindOrCreateNode(types.NodeKindHost, "DC02", "DC02", map[string]any{"role": "dc"})
	e2 := g.AppendEdge(src2, dst2, types.EdgeKindAuthenticatedAs, time.Unix(0, 0).UTC(), 1, "evt-2")
	s.SetAuthKind(e2, "kerberos")
	score2 := s.freqRarity(e2, g)

	if score1 <= score2 {
		t.Errorf("expected first auth tuple to score higher: %f vs %f", score1, score2)
	}
}

// Temporal decay: with the same node touched twice, an edge arriving exactly
// one half-life later should score factor ~0.5; arriving "now" should score ~1.
func TestTemporalDecay_HalfLifeYieldsHalfFactor(t *testing.T) {
	halfLife := 30 * time.Second
	s := New(Config{HalfLife: halfLife})
	g := graph.New()

	parent := g.FindOrCreateNode(types.NodeKindProcess, "p", "cmd.exe", nil)
	child := g.FindOrCreateNode(types.NodeKindProcess, "c", "powershell.exe", nil)
	t0 := time.Unix(1700000000, 0).UTC()

	// First edge: no prior touch, factor must be 1.0.
	e1 := g.AppendEdge(parent, child, types.EdgeKindSpawned, t0, 1, "evt-1")
	if got := s.temporalDecay(e1); math.Abs(got-1.0) > 1e-9 {
		t.Errorf("first-touch decay factor = %f, want 1.0", got)
	}
	s.observeTouch(e1)

	// Second edge on the same node, one half-life later: factor must be ~0.5.
	e2 := g.AppendEdge(parent, child, types.EdgeKindSpawned, t0.Add(halfLife), 1, "evt-2")
	got := s.temporalDecay(e2)
	if math.Abs(got-0.5) > 0.01 {
		t.Errorf("half-life decay factor = %f, want ~0.5", got)
	}
}

// Structural lift: edges touching a sensitive node receive a multiplier > 1.
func TestStructuralLift_SensitiveNodeAmplifies(t *testing.T) {
	s := New(Config{SensitiveLabels: []string{"lsass.exe"}, LiftFactor: 2.5})
	g := graph.New()

	mundaneSrc := g.FindOrCreateNode(types.NodeKindProcess, "ms", "explorer.exe", nil)
	mundaneDst := g.FindOrCreateNode(types.NodeKindProcess, "md", "notepad.exe", nil)
	mundane := g.AppendEdge(mundaneSrc, mundaneDst, types.EdgeKindSpawned, time.Unix(0, 0).UTC(), 1, "evt-m")
	if got := s.structuralLift(mundane, g); math.Abs(got-1.0) > 1e-9 {
		t.Errorf("mundane lift = %f, want 1.0", got)
	}

	attacker := g.FindOrCreateNode(types.NodeKindProcess, "a", "powershell.exe", nil)
	lsass := g.FindOrCreateNode(types.NodeKindProcess, "l", "lsass.exe", nil)
	sensitive := g.AppendEdge(attacker, lsass, types.EdgeKindDumpedMemoryOf, time.Unix(0, 0).UTC(), 1, "evt-s")
	if got := s.structuralLift(sensitive, g); math.Abs(got-2.5) > 1e-9 {
		t.Errorf("sensitive lift = %f, want 2.5", got)
	}
}

// Structural lift: edges that cross a host boundary also receive the lift.
func TestStructuralLift_CrossHostAmplifies(t *testing.T) {
	s := New(Config{LiftFactor: 2.0})
	g := graph.New()

	srcLocal := g.FindOrCreateNode(types.NodeKindProcess, "a", "cmd.exe", map[string]any{"host": "WS01"})
	dstLocal := g.FindOrCreateNode(types.NodeKindProcess, "b", "powershell.exe", map[string]any{"host": "WS01"})
	local := g.AppendEdge(srcLocal, dstLocal, types.EdgeKindSpawned, time.Unix(0, 0).UTC(), 1, "evt-l")
	if got := s.structuralLift(local, g); math.Abs(got-1.0) > 1e-9 {
		t.Errorf("same-host lift = %f, want 1.0", got)
	}

	srcRemote := g.FindOrCreateNode(types.NodeKindProcess, "c", "psexec.exe", map[string]any{"host": "WS01"})
	dstRemote := g.FindOrCreateNode(types.NodeKindProcess, "d", "cmd.exe", map[string]any{"host": "DC01"})
	remote := g.AppendEdge(srcRemote, dstRemote, types.EdgeKindSpawned, time.Unix(0, 0).UTC(), 1, "evt-r")
	if got := s.structuralLift(remote, g); math.Abs(got-2.0) > 1e-9 {
		t.Errorf("cross-host lift = %f, want 2.0", got)
	}
}

// Composite ScoreEdge multiplies the three terms together. A novel cross-host
// edge touching a sensitive node early in the chain should score strictly
// higher than a stale, commodity, local edge.
func TestScoreEdge_CompositeRanksKillChainAboveNoise(t *testing.T) {
	s := New(Config{
		HalfLife:        time.Minute,
		SensitiveLabels: []string{"lsass.exe"},
		LiftFactor:      2.0,
		Threshold:       math.Inf(1), // never trigger in this test
	})
	g := graph.New()

	t0 := time.Unix(1700000000, 0).UTC()
	// Pre-train freqRarity on a benign baseline so subsequent "cmd.exe -> notepad.exe"
	// observations look common.
	for i := 0; i < 5; i++ {
		p := g.FindOrCreateNode(types.NodeKindProcess, "bp"+itoa(i), "cmd.exe", map[string]any{"host": "WS01"})
		c := g.FindOrCreateNode(types.NodeKindProcess, "bc"+itoa(i), "notepad.exe", map[string]any{"host": "WS01"})
		e := g.AppendEdge(p, c, types.EdgeKindSpawned, t0.Add(time.Duration(i)*time.Minute), 1, "noise-"+itoa(i))
		s.ScoreEdge(e, g)
	}

	noiseP := g.FindOrCreateNode(types.NodeKindProcess, "nP", "cmd.exe", map[string]any{"host": "WS01"})
	noiseC := g.FindOrCreateNode(types.NodeKindProcess, "nC", "notepad.exe", map[string]any{"host": "WS01"})
	noiseEdge := g.AppendEdge(noiseP, noiseC, types.EdgeKindSpawned, t0.Add(time.Hour), 1, "noise-x")
	noiseScore := s.ScoreEdge(noiseEdge, g)

	killP := g.FindOrCreateNode(types.NodeKindProcess, "kP", "powershell.exe", map[string]any{"host": "WS01"})
	killC := g.FindOrCreateNode(types.NodeKindProcess, "kC", "lsass.exe", map[string]any{"host": "DC01"})
	killEdge := g.AppendEdge(killP, killC, types.EdgeKindDumpedMemoryOf, t0.Add(time.Hour), 1, "kill-x")
	killScore := s.ScoreEdge(killEdge, g)

	if !(killScore > noiseScore) {
		t.Errorf("expected kill-chain edge score (%f) > noise edge score (%f)", killScore, noiseScore)
	}
}

// Threshold signal: once a connected component's mean edge score crosses the
// trigger threshold, Signals() must emit at least one Signal naming a node in
// that component.
func TestScoreEdge_ThresholdEmitsSignal(t *testing.T) {
	s := New(Config{
		HalfLife:        time.Minute,
		SensitiveLabels: []string{"lsass.exe"},
		LiftFactor:      3.0,
		Threshold:       0.5,
	})
	g := graph.New()

	t0 := time.Unix(1700000000, 0).UTC()
	a := g.FindOrCreateNode(types.NodeKindProcess, "a", "winword.exe", map[string]any{"host": "WS01"})
	b := g.FindOrCreateNode(types.NodeKindProcess, "b", "powershell.exe", map[string]any{"host": "WS01"})
	c := g.FindOrCreateNode(types.NodeKindProcess, "c", "lsass.exe", map[string]any{"host": "WS01"})

	e1 := g.AppendEdge(a, b, types.EdgeKindSpawned, t0, 1, "evt-1")
	e2 := g.AppendEdge(b, c, types.EdgeKindDumpedMemoryOf, t0.Add(2*time.Second), 1, "evt-2")
	s.ScoreEdge(e1, g)
	s.ScoreEdge(e2, g)

	select {
	case sig := <-s.Signals():
		if sig.Mean < 0.5 {
			t.Errorf("signal mean = %f, want >= 0.5", sig.Mean)
		}
		if sig.HotNode != a.ID && sig.HotNode != b.ID && sig.HotNode != c.ID {
			t.Errorf("HotNode = %q, want one of %q/%q/%q", sig.HotNode, a.ID, b.ID, c.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("threshold was crossed but Signals() did not emit within 1s")
	}
}

// Sub-threshold composite must NOT emit a signal.
func TestScoreEdge_SubThresholdDoesNotEmit(t *testing.T) {
	s := New(Config{Threshold: 999})
	g := graph.New()
	p := g.FindOrCreateNode(types.NodeKindProcess, "p", "cmd.exe", nil)
	c := g.FindOrCreateNode(types.NodeKindProcess, "c", "notepad.exe", nil)
	e := g.AppendEdge(p, c, types.EdgeKindSpawned, time.Unix(0, 0).UTC(), 1, "evt-1")
	s.ScoreEdge(e, g)
	select {
	case sig := <-s.Signals():
		t.Errorf("did not expect signal, got %+v", sig)
	case <-time.After(50 * time.Millisecond):
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var digits []byte
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	return string(digits)
}

// awaitSignal returns the next buffered signal, failing if none arrives.
func awaitSignal(t *testing.T, s *Scorer) Signal {
	t.Helper()
	select {
	case sig := <-s.Signals():
		return sig
	case <-time.After(time.Second):
		t.Fatal("expected a signal but none arrived")
		return Signal{}
	}
}

// Incident identity: a fresh component mints a new id; growing that component
// keeps the same id; a disjoint component gets a different id; connecting two
// components merges them into the earliest id.
func TestResolveIncident_MintReuseMerge(t *testing.T) {
	s := New(Config{Threshold: 0.0001})
	g := graph.New()
	t0 := time.Unix(1700000000, 0).UTC()

	a := g.FindOrCreateNode(types.NodeKindProcess, "WS01:1", "winword.exe", map[string]any{"host": "WS01"})
	b := g.FindOrCreateNode(types.NodeKindProcess, "WS01:2", "powershell.exe", map[string]any{"host": "WS01"})
	e1 := g.AppendEdge(a, b, types.EdgeKindSpawned, t0, 1, "evt-1")
	s.ScoreEdge(e1, g)
	id1 := awaitSignal(t, s).IncidentID
	if id1 == "" {
		t.Fatal("expected an incident id on the first signal")
	}

	// Growth: same component, same id.
	c := g.FindOrCreateNode(types.NodeKindProcess, "WS01:3", "lsass.exe", map[string]any{"host": "WS01"})
	e2 := g.AppendEdge(b, c, types.EdgeKindDumpedMemoryOf, t0.Add(time.Second), 1, "evt-2")
	s.ScoreEdge(e2, g)
	if got := awaitSignal(t, s).IncidentID; got != id1 {
		t.Errorf("growth incident id = %q, want same as %q", got, id1)
	}

	// Disjoint component on WS02: a different incident.
	x := g.FindOrCreateNode(types.NodeKindProcess, "WS02:1", "winword.exe", map[string]any{"host": "WS02"})
	y := g.FindOrCreateNode(types.NodeKindProcess, "WS02:2", "powershell.exe", map[string]any{"host": "WS02"})
	e3 := g.AppendEdge(x, y, types.EdgeKindSpawned, t0.Add(2*time.Second), 1, "evt-3")
	s.ScoreEdge(e3, g)
	id2 := awaitSignal(t, s).IncidentID
	if id2 == id1 {
		t.Errorf("disjoint component reused incident id %q, want a new one", id1)
	}

	// Merge: connect the two components; the later incident is absorbed.
	e4 := g.AppendEdge(c, x, types.EdgeKindSpawned, t0.Add(3*time.Second), 1, "evt-4")
	s.ScoreEdge(e4, g)
	if got := awaitSignal(t, s).IncidentID; got != id1 {
		t.Errorf("merged component incident id = %q, want earliest %q", got, id1)
	}
}
