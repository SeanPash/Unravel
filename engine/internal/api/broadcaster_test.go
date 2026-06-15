package api

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/luigifernandez/unravel/engine/internal/types"
)

func mustMessage(t *testing.T, payload any) types.WSMessage {
	t.Helper()
	msg, err := types.NewMessage(types.MsgTypeScoreUpdate, payload)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestBroadcasterFansOutToAllSubscribers(t *testing.T) {
	t.Parallel()
	b := NewBroadcaster()
	defer b.Close()

	subs := []*Subscriber{b.Subscribe(), b.Subscribe(), b.Subscribe()}
	msg := mustMessage(t, types.ScoreUpdatePayload{EdgeID: "e1", Score: 0.5})

	delivered := b.Send(msg)
	if delivered != 3 {
		t.Fatalf("delivered = %d, want 3", delivered)
	}
	for i, s := range subs {
		select {
		case got := <-s.Out():
			if got.Type != types.MsgTypeScoreUpdate {
				t.Errorf("sub %d type = %s", i, got.Type)
			}
			var p types.ScoreUpdatePayload
			if err := json.Unmarshal(got.Payload, &p); err != nil {
				t.Errorf("sub %d payload: %v", i, err)
			}
			if p.EdgeID != "e1" || p.Score != 0.5 {
				t.Errorf("sub %d payload = %+v", i, p)
			}
		case <-time.After(time.Second):
			t.Errorf("sub %d did not receive message", i)
		}
	}
}

func TestBroadcasterDropsSlowClient(t *testing.T) {
	t.Parallel()
	// No backlog: the outbox capacity is exactly SlowClientBuffer, so the drop
	// threshold is deterministic and independent of snapshot seeding.
	b := NewBroadcasterWithBacklog(0)
	defer b.Close()
	sub := b.Subscribe()
	msg := mustMessage(t, types.ScoreUpdatePayload{})

	// Fill the outbox without ever reading.
	for i := 0; i < SlowClientBuffer; i++ {
		b.Send(msg)
	}
	if b.DropCount.Load() != 0 {
		t.Fatalf("premature drop: %d", b.DropCount.Load())
	}

	// The next send must drop the slow client and close its channel.
	b.Send(msg)
	if got := b.DropCount.Load(); got != 1 {
		t.Errorf("DropCount = %d, want 1", got)
	}
	// Drain the outbox; it should be closed once empty.
	drained := 0
	for range sub.Out() {
		drained++
	}
	if drained != SlowClientBuffer {
		t.Errorf("drained = %d, want %d", drained, SlowClientBuffer)
	}
	if b.Count() != 0 {
		t.Errorf("subscriber not removed: count = %d", b.Count())
	}
}

func TestBroadcasterUnsubscribeIsIdempotent(t *testing.T) {
	t.Parallel()
	b := NewBroadcaster()
	defer b.Close()
	sub := b.Subscribe()
	sub.Unsubscribe()
	sub.Unsubscribe() // must not panic
	if b.Count() != 0 {
		t.Fatalf("count = %d", b.Count())
	}
}

func TestBroadcasterReplaysBacklogToLateSubscriber(t *testing.T) {
	t.Parallel()
	b := NewBroadcaster()
	defer b.Close()

	// Send several messages with no subscriber connected (e.g. a replay that
	// finished before the browser opened).
	want := []string{"e1", "e2", "e3", "e4"}
	for _, id := range want {
		b.Send(mustMessage(t, types.ScoreUpdatePayload{EdgeID: id}))
	}

	// A client that joins now must receive the earlier messages, in order,
	// before any live message.
	sub := b.Subscribe()
	for i, edgeID := range want {
		select {
		case got := <-sub.Out():
			var p types.ScoreUpdatePayload
			if err := json.Unmarshal(got.Payload, &p); err != nil {
				t.Fatalf("backlog %d payload: %v", i, err)
			}
			if p.EdgeID != edgeID {
				t.Fatalf("backlog %d edge = %q, want %q", i, p.EdgeID, edgeID)
			}
		case <-time.After(time.Second):
			t.Fatalf("late subscriber did not receive backlog message %d (%s)", i, edgeID)
		}
	}

	// Live delivery continues exactly from the end of the backlog: a new Send
	// arrives next, with nothing lost or duplicated across the seam.
	b.Send(mustMessage(t, types.ScoreUpdatePayload{EdgeID: "e5"}))
	select {
	case got := <-sub.Out():
		var p types.ScoreUpdatePayload
		if err := json.Unmarshal(got.Payload, &p); err != nil {
			t.Fatalf("live payload: %v", err)
		}
		if p.EdgeID != "e5" {
			t.Fatalf("live edge = %q, want e5", p.EdgeID)
		}
	case <-time.After(time.Second):
		t.Fatal("late subscriber did not receive live message after backlog")
	}
}

func TestBroadcasterBacklogIsCapped(t *testing.T) {
	t.Parallel()
	const cap = 3
	b := NewBroadcasterWithBacklog(cap)
	defer b.Close()

	// Send more than the cap with no subscriber connected.
	for _, id := range []string{"e1", "e2", "e3", "e4", "e5"} {
		b.Send(mustMessage(t, types.ScoreUpdatePayload{EdgeID: id}))
	}
	if got := b.BacklogLen(); got != cap {
		t.Fatalf("BacklogLen = %d, want %d", got, cap)
	}

	// A late subscriber sees the most recent window (oldest evicted), in order.
	sub := b.Subscribe()
	want := []string{"e3", "e4", "e5"}
	for i, edgeID := range want {
		select {
		case got := <-sub.Out():
			var p types.ScoreUpdatePayload
			if err := json.Unmarshal(got.Payload, &p); err != nil {
				t.Fatalf("backlog %d payload: %v", i, err)
			}
			if p.EdgeID != edgeID {
				t.Fatalf("backlog %d edge = %q, want %q", i, p.EdgeID, edgeID)
			}
		case <-time.After(time.Second):
			t.Fatalf("did not receive capped backlog message %d (%s)", i, edgeID)
		}
	}
	select {
	case extra := <-sub.Out():
		t.Fatalf("unexpected extra backlog message: %+v", extra)
	default:
	}
}

func TestBroadcasterNoBacklogWhenDisabled(t *testing.T) {
	t.Parallel()
	b := NewBroadcasterWithBacklog(0)
	defer b.Close()
	b.Send(mustMessage(t, types.ScoreUpdatePayload{EdgeID: "e1"}))
	if got := b.BacklogLen(); got != 0 {
		t.Fatalf("BacklogLen = %d, want 0", got)
	}
	sub := b.Subscribe()
	select {
	case got := <-sub.Out():
		t.Fatalf("disabled backlog still replayed: %+v", got)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestBroadcasterCloseClosesOutboxes(t *testing.T) {
	t.Parallel()
	b := NewBroadcaster()
	sub := b.Subscribe()
	b.Close()
	if _, ok := <-sub.Out(); ok {
		t.Fatal("outbox not closed after Close")
	}
	// Subscribe-after-Close returns an inert subscriber that never gets messages.
	zombie := b.Subscribe()
	if zombie == nil {
		t.Fatal("Subscribe returned nil")
	}
	if b.Count() != 0 {
		t.Errorf("zombie counted: %d", b.Count())
	}
}
