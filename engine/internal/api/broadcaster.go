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
type Broadcaster struct {
	mu     sync.RWMutex
	nextID atomic.Uint64
	subs   map[uint64]*Subscriber
	closed bool
	// DropCount counts how many subscribers were force-dropped due to slow
	// reads. Exposed for tests and operational metrics.
	DropCount atomic.Uint64
}

// NewBroadcaster returns an empty broadcaster ready to accept subscribers.
func NewBroadcaster() *Broadcaster {
	return &Broadcaster{subs: make(map[uint64]*Subscriber)}
}

// Subscribe registers a new subscriber and returns a handle. The caller is
// responsible for Unsubscribe in a defer.
func (b *Broadcaster) Subscribe() *Subscriber {
	id := b.nextID.Add(1)
	s := &Subscriber{
		id:  id,
		out: make(chan types.WSMessage, SlowClientBuffer),
		bc:  b,
	}
	b.mu.Lock()
	if !b.closed {
		b.subs[id] = s
	}
	b.mu.Unlock()
	return s
}

// Send fans msg out to every subscriber. Returns the number of subscribers
// that received the message; subscribers whose outbox was full are dropped and
// counted in DropCount.
func (b *Broadcaster) Send(msg types.WSMessage) int {
	b.mu.RLock()
	// Snapshot the subscriber list so we don't hold the lock during sends.
	snap := make([]*Subscriber, 0, len(b.subs))
	for _, s := range b.subs {
		snap = append(snap, s)
	}
	b.mu.RUnlock()

	delivered := 0
	var dropIDs []uint64
	for _, s := range snap {
		select {
		case s.out <- msg:
			delivered++
		default:
			dropIDs = append(dropIDs, s.id)
		}
	}
	for _, id := range dropIDs {
		b.DropCount.Add(1)
		b.unsubscribe(id)
	}
	return delivered
}

// Close removes all subscribers and rejects future Subscribe calls. After
// Close, the broadcaster cannot be reused.
func (b *Broadcaster) Close() {
	b.mu.Lock()
	b.closed = true
	subs := b.subs
	b.subs = nil
	b.mu.Unlock()
	for _, s := range subs {
		close(s.out)
	}
}

// Count returns the current subscriber count. Used in tests and could feed a
// /metrics endpoint later.
func (b *Broadcaster) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs)
}

func (b *Broadcaster) unsubscribe(id uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s, ok := b.subs[id]
	if !ok {
		return
	}
	delete(b.subs, id)
	close(s.out)
}
