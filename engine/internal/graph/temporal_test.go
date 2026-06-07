package graph

import (
	"sort"
	"testing"
	"time"

	"github.com/luigifernandez/unravel/engine/internal/types"
)

func mkEdge(id, src, dst string, ts time.Time) *types.Edge {
	return &types.Edge{
		ID:   id,
		Src:  src,
		Dst:  dst,
		Kind: types.EdgeKindSpawned,
		TS:   ts.Unix(),
	}
}

func TestTemporalIndex_QueryIncludesEndpoints(t *testing.T) {
	ti := NewTemporalIndex(time.Minute)
	base := time.Date(2026, 6, 5, 19, 30, 0, 0, time.UTC)
	e := mkEdge("e1", "proc-A", "proc-B", base)
	ti.Insert(e)

	if got := ti.Query("proc-A", base.Add(-time.Second), base.Add(time.Second)); len(got) != 1 || got[0] != e {
		t.Errorf("Query(src) = %+v, want [e1]", got)
	}
	if got := ti.Query("proc-B", base.Add(-time.Second), base.Add(time.Second)); len(got) != 1 || got[0] != e {
		t.Errorf("Query(dst) = %+v, want [e1]", got)
	}
}

func TestTemporalIndex_QueryWindowFiltering(t *testing.T) {
	ti := NewTemporalIndex(time.Minute)
	base := time.Date(2026, 6, 5, 19, 0, 0, 0, time.UTC)

	edges := []*types.Edge{
		mkEdge("e1", "n", "x", base.Add(0*time.Minute)),
		mkEdge("e2", "n", "x", base.Add(2*time.Minute)),
		mkEdge("e3", "n", "x", base.Add(5*time.Minute)),
		mkEdge("e4", "n", "x", base.Add(10*time.Minute)),
		mkEdge("e5", "n", "x", base.Add(30*time.Minute)),
	}
	for _, e := range edges {
		ti.Insert(e)
	}

	got := ti.Query("n", base.Add(1*time.Minute), base.Add(11*time.Minute))
	ids := edgeIDs(got)
	sort.Strings(ids)
	want := []string{"e2", "e3", "e4"}
	if !equalStrings(ids, want) {
		t.Errorf("Query 1m-11m = %v, want %v", ids, want)
	}
}

func TestTemporalIndex_BoundsAreInclusive(t *testing.T) {
	ti := NewTemporalIndex(time.Minute)
	base := time.Date(2026, 6, 5, 19, 0, 0, 0, time.UTC)

	ti.Insert(mkEdge("e1", "n", "x", base))
	ti.Insert(mkEdge("e2", "n", "x", base.Add(time.Minute)))

	got := ti.Query("n", base, base.Add(time.Minute))
	if len(got) != 2 {
		t.Errorf("inclusive query returned %d edges, want 2", len(got))
	}
}

func TestTemporalIndex_NoMatchReturnsNil(t *testing.T) {
	ti := NewTemporalIndex(time.Minute)
	base := time.Date(2026, 6, 5, 19, 0, 0, 0, time.UTC)
	ti.Insert(mkEdge("e1", "n", "x", base))

	if got := ti.Query("n", base.Add(time.Hour), base.Add(2*time.Hour)); got != nil {
		t.Errorf("Query outside window = %+v, want nil", got)
	}
	if got := ti.Query("absent", base.Add(-time.Hour), base.Add(time.Hour)); got != nil {
		t.Errorf("Query absent node = %+v, want nil", got)
	}
}

func TestTemporalIndex_RejectsReversedWindow(t *testing.T) {
	ti := NewTemporalIndex(time.Minute)
	base := time.Date(2026, 6, 5, 19, 0, 0, 0, time.UTC)
	ti.Insert(mkEdge("e1", "n", "x", base))

	if got := ti.Query("n", base.Add(time.Hour), base); got != nil {
		t.Errorf("Query with to<from = %+v, want nil", got)
	}
}

func TestTemporalIndex_SelfLoopCountedOnce(t *testing.T) {
	ti := NewTemporalIndex(time.Minute)
	base := time.Date(2026, 6, 5, 19, 0, 0, 0, time.UTC)
	ti.Insert(mkEdge("e1", "n", "n", base))

	got := ti.Query("n", base.Add(-time.Second), base.Add(time.Second))
	if len(got) != 1 {
		t.Errorf("self-loop Query returned %d edges, want 1", len(got))
	}
}

func TestTemporalIndex_DefaultBucketSize(t *testing.T) {
	ti := NewTemporalIndex(0)
	base := time.Date(2026, 6, 5, 19, 0, 0, 0, time.UTC)
	ti.Insert(mkEdge("e1", "n", "x", base))
	ti.Insert(mkEdge("e2", "n", "x", base.Add(30*time.Second)))

	if ti.BucketCount() != 1 {
		t.Errorf("default bucket size: BucketCount = %d, want 1", ti.BucketCount())
	}
}

func edgeIDs(es []*types.Edge) []string {
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.ID)
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
