package graph

import (
	"sort"
	"sync"
	"time"

	"github.com/luigifernandez/unravel/engine/internal/types"
)

// DefaultBucketSize is the temporal index bucket width. One minute strikes a
// balance between bucket count growth (we keep buckets in a sorted slice) and
// the typical resolution of security telemetry windows.
const DefaultBucketSize = time.Minute

// TemporalIndex answers "which edges touching node X fall in window [t1, t2]?"
// in O(log n + k). Edges are bucketed by floor(ts/bucketSize). Each query does
// a binary search on the sorted bucket keys, then walks the matching buckets.
//
// The index is intentionally separate from Graph so the pipeline can choose
// when to refresh it (e.g. on every AppendEdge for streaming mode, or in batch
// after replay).
type TemporalIndex struct {
	mu         sync.RWMutex
	bucketSize time.Duration
	buckets    map[int64]*bucket
	// sortedKeys mirrors len(buckets); maintained sorted for log(n) range scans.
	sortedKeys []int64
}

type bucket struct {
	// edgesByNode maps both endpoints (Src and Dst) to the edges that touch
	// them within this bucket. Symmetric storage avoids per-query branching.
	edgesByNode map[string][]*types.Edge
}

// NewTemporalIndex returns an empty index using the given bucket size. If
// bucketSize is non-positive, DefaultBucketSize is used.
func NewTemporalIndex(bucketSize time.Duration) *TemporalIndex {
	if bucketSize <= 0 {
		bucketSize = DefaultBucketSize
	}
	return &TemporalIndex{
		bucketSize: bucketSize,
		buckets:    make(map[int64]*bucket),
	}
}

func (ti *TemporalIndex) bucketKey(ts time.Time) int64 {
	return ts.Unix() / int64(ti.bucketSize.Seconds())
}

// Insert adds an edge to the index under both its endpoints.
func (ti *TemporalIndex) Insert(e *types.Edge) {
	ts := time.Unix(e.TS, 0).UTC()
	key := ti.bucketKey(ts)
	ti.mu.Lock()
	defer ti.mu.Unlock()
	b, ok := ti.buckets[key]
	if !ok {
		b = &bucket{edgesByNode: make(map[string][]*types.Edge)}
		ti.buckets[key] = b
		ti.insertSortedKey(key)
	}
	b.edgesByNode[e.Src] = append(b.edgesByNode[e.Src], e)
	if e.Dst != e.Src {
		b.edgesByNode[e.Dst] = append(b.edgesByNode[e.Dst], e)
	}
}

func (ti *TemporalIndex) insertSortedKey(key int64) {
	i := sort.Search(len(ti.sortedKeys), func(i int) bool { return ti.sortedKeys[i] >= key })
	ti.sortedKeys = append(ti.sortedKeys, 0)
	copy(ti.sortedKeys[i+1:], ti.sortedKeys[i:])
	ti.sortedKeys[i] = key
}

// Query returns the edges touching nodeID whose timestamp lies in [from, to].
// Bounds are inclusive. Edges may be returned in arbitrary order within a
// bucket; callers that need a strict timeline should sort the result.
func (ti *TemporalIndex) Query(nodeID string, from, to time.Time) []*types.Edge {
	if to.Before(from) {
		return nil
	}
	startKey := ti.bucketKey(from)
	endKey := ti.bucketKey(to)
	fromUnix := from.Unix()
	toUnix := to.Unix()

	ti.mu.RLock()
	defer ti.mu.RUnlock()

	startIdx := sort.Search(len(ti.sortedKeys), func(i int) bool { return ti.sortedKeys[i] >= startKey })
	var out []*types.Edge
	for i := startIdx; i < len(ti.sortedKeys); i++ {
		k := ti.sortedKeys[i]
		if k > endKey {
			break
		}
		b := ti.buckets[k]
		if b == nil {
			continue
		}
		for _, e := range b.edgesByNode[nodeID] {
			if e.TS >= fromUnix && e.TS <= toUnix {
				out = append(out, e)
			}
		}
	}
	return out
}

// BucketCount returns the number of populated time buckets. Mostly useful for
// tests and debug output.
func (ti *TemporalIndex) BucketCount() int {
	ti.mu.RLock()
	defer ti.mu.RUnlock()
	return len(ti.buckets)
}
