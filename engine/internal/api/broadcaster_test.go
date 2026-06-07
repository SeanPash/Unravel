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
	b := NewBroadcaster()
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
