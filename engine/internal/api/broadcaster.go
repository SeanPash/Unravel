// Package api owns the HTTP server, WebSocket upgrade handler, and the
// fan-out Broadcaster that pushes engine events to every connected UI client.
// The broadcaster is deliberately non-blocking: a slow consumer is unsubscribed
// rather than allowed to back up the streaming pipeline.
package api

import (
	"sync"
	"sync/atomic"

	"github.com/luigifernandez/unravel/engine/internal/types"
)

// SlowClientBuffer is the per-subscriber outbox depth. When a subscriber falls
// this many messages behind, the broadcaster drops it.
const SlowClientBuffer = 64

// DefaultBacklogCap is the default number of past messages the broadcaster
// retains for snapshot-on-connect. A late client (browser refresh, or opening
// the page after a replay finished) receives this backlog before live messages
// so the full investigation renders regardless of when it connected. A demo
// replay produces well under this many messages; the cap only bounds memory if
// the engine runs unbounded in live mode. When the backlog is full the oldest
// message is evicted, so a client joining after the cap is exceeded sees the
// most recent window rather than the very first events.
const DefaultBacklogCap = 4096

// Subscriber is a single client's outgoing channel and an identifier the
// broadcaster uses for unsubscribe.
type Subscriber struct {
	id  uint64
	out chan types.WSMessage
	bc  *Broadcaster
}

// Out exposes the channel a WebSocket writer reads from. Closed when the
// subscriber is dropped.
func (s *Subscriber) Out() <-chan types.WSMessage { return s.out }

// Unsubscribe removes the subscriber and closes its outbox. Safe to call more
// than once; subsequent calls are no-ops.
func (s *Subscriber) Unsubscribe() { s.bc.unsubscribe(s.id) }

// Broadcaster fans WSMessages out to every active Subscriber. Send is
// non-blocking: if a subscriber's outbox is full, the broadcaster drops that
// subscriber rather than stalling.
//
// The broadcaster also retains an ordered backlog of every message it has sent
// (capped at backlogCap). A newly subscribed client is seeded with this backlog
// before it receives any live message, so a late join reconstructs the full
// current state: replaying graph_update and score_update messages in order
// rebuilds the graph exactly, and replaying chain_result/narration/
// threat_intel/agent_activity restores the side panels.
type Broadcaster struct {
	mu     sync.Mutex
	nextID atomic.Uint64
	subs   map[uint64]*Subscriber
	closed bool
	// backlog is the ordered history of sent messages, capped at backlogCap.
	// It is appended under mu in Send and copied under mu in Subscribe, which is
	// what makes "capture the backlog, then register for live delivery" atomic:
	// a subscriber's snapshot is a consistent prefix of the global send order and
	// live delivery continues exactly from that point, with no message lost or
	// duplicated across the seam.
	backlog    []types.WSMessage
	backlogCap int
	// DropCount counts how many subscribers were force-dropped due to slow
	// reads. Exposed for tests and operational metrics.
	DropCount atomic.Uint64
}

// NewBroadcaster returns an empty broadcaster ready to accept subscribers, with
// the default backlog cap (DefaultBacklogCap).
func NewBroadcaster() *Broadcaster {
	return NewBroadcasterWithBacklog(DefaultBacklogCap)
}

// NewBroadcasterWithBacklog returns an empty broadcaster that retains up to
// backlogCap past messages for snapshot-on-connect. A non-positive cap disables
// the backlog (no snapshot is replayed to late joiners).
func NewBroadcasterWithBacklog(backlogCap int) *Broadcaster {
	if backlogCap < 0 {
		backlogCap = 0
	}
	return &Broadcaster{
		subs:       make(map[uint64]*Subscriber),
		backlogCap: backlogCap,
	}
}

// Subscribe registers a new subscriber and returns a handle. The caller is
// responsible for Unsubscribe in a defer. The returned subscriber's outbox is
// pre-seeded with the current backlog (snapshot-on-connect) so a late join
// renders the full current state before any live message arrives.
//
// Backlog capture and live registration happen under a single lock: the
// subscriber is added to subs (so future Sends reach it) in the same critical
// section that copies the backlog into its outbox. No Send can interleave
// between the two, so the snapshot plus the live stream form one gap-free,
// duplicate-free ordering.
func (b *Broadcaster) Subscribe() *Subscriber {
	id := b.nextID.Add(1)
	// Size the outbox so the backlog snapshot always fits without forcing an
	// immediate slow-client drop on a fresh, well-behaved connection. Live depth
	// (SlowClientBuffer) is added on top of the snapshot capacity.
	s := &Subscriber{
		id:  id,
		out: make(chan types.WSMessage, b.backlogCap+SlowClientBuffer),
		bc:  b,
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		// Subscribe-after-Close returns an inert subscriber that never gets
		// messages. Leave its outbox open and empty; the caller's read loop will
		// idle on it until the request context ends.
		return s
	}
	// Seed the backlog before registering for live delivery. This send cannot
	// block: the outbox capacity is at least len(backlog).
	for _, msg := range b.backlog {
		s.out <- msg
	}
	b.subs[id] = s
	return s
}

// Send fans msg out to every subscriber and appends it to the backlog. Returns
// the number of subscribers that received the message; subscribers whose outbox
// was full are dropped and counted in DropCount.
func (b *Broadcaster) Send(msg types.WSMessage) int {
	// Hold the lock across both the backlog append and the non-blocking sends.
	// The sends use a select with a default case so they never block, which
	// keeps the critical section bounded. Holding the lock here is what makes
	// the channel send safe: an unsubscribe (or Close) that wants to close a
	// subscriber's outbox needs the same lock, so it cannot close a channel out
	// from under an in-flight send. Closing outside this guard caused a
	// "send on closed channel" panic when a client disconnected (or was dropped
	// by a concurrent Send) mid-broadcast.
	//
	// Appending to the backlog under the same lock keeps the backlog a faithful
	// prefix of what every live subscriber has seen, which is the invariant
	// Subscribe relies on for a clean snapshot/live seam.
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return 0
	}
	b.appendBacklog(msg)
	delivered := 0
	var dropIDs []uint64
	for id, s := range b.subs {
		select {
		case s.out <- msg:
			delivered++
		default:
			dropIDs = append(dropIDs, id)
		}
	}
	// Drop slow clients while still holding the lock; unsubscribeLocked assumes
	// the caller holds mu, so there is no lock round-trip and no deadlock.
	for _, id := range dropIDs {
		b.DropCount.Add(1)
		b.unsubscribeLocked(id)
	}
	b.mu.Unlock()
	return delivered
}

// appendBacklog records msg in the bounded history. Caller must hold b.mu.
// When the backlog is at capacity the oldest entry is evicted.
func (b *Broadcaster) appendBacklog(msg types.WSMessage) {
	if b.backlogCap == 0 {
		return
	}
	if len(b.backlog) >= b.backlogCap {
		// Drop the oldest entry. copy keeps the slice from growing without bound
		// and avoids retaining the evicted message.
		copy(b.backlog, b.backlog[1:])
		b.backlog[len(b.backlog)-1] = msg
		return
	}
	b.backlog = append(b.backlog, msg)
}

// Close removes all subscribers and rejects future Subscribe calls. After
// Close, the broadcaster cannot be reused.
func (b *Broadcaster) Close() {
	b.mu.Lock()
	b.closed = true
	subs := b.subs
	b.subs = nil
	b.backlog = nil
	b.mu.Unlock()
	for _, s := range subs {
		close(s.out)
	}
}

// Count returns the current subscriber count. Used in tests and could feed a
// /metrics endpoint later.
func (b *Broadcaster) Count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subs)
}

// BacklogLen returns the number of messages currently retained for
// snapshot-on-connect. Exposed for tests.
func (b *Broadcaster) BacklogLen() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.backlog)
}

func (b *Broadcaster) unsubscribe(id uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.unsubscribeLocked(id)
}

// unsubscribeLocked removes a subscriber and closes its outbox. Caller must
// hold b.mu.
func (b *Broadcaster) unsubscribeLocked(id uint64) {
	s, ok := b.subs[id]
	if !ok {
		return
	}
	delete(b.subs, id)
	close(s.out)
}
