package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/luigifernandez/unravel/engine/internal/types"
)

func TestServerWebSocketReceivesBroadcast(t *testing.T) {
	t.Parallel()
	b := NewBroadcaster()
	defer b.Close()
	s := NewServer(b, nil)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	conn, _, err := websocket.DefaultDialer.Dial(WSURL(srv.URL), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Give the server a moment to register the subscriber.
	deadline := time.Now().Add(time.Second)
	for b.Count() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("server never registered subscriber")
		}
		time.Sleep(10 * time.Millisecond)
	}

	msg, err := types.NewMessage(types.MsgTypeScoreUpdate, types.ScoreUpdatePayload{EdgeID: "e1", Score: 0.7})
	if err != nil {
		t.Fatal(err)
	}
	if delivered := b.Send(msg); delivered != 1 {
		t.Fatalf("delivered = %d", delivered)
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var got types.WSMessage
	if err := conn.ReadJSON(&got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.Type != types.MsgTypeScoreUpdate {
		t.Errorf("type = %s", got.Type)
	}
	var p types.ScoreUpdatePayload
	if err := json.Unmarshal(got.Payload, &p); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if p.EdgeID != "e1" || p.Score != 0.7 {
		t.Errorf("payload = %+v", p)
	}
}

func TestServerHealthz(t *testing.T) {
	t.Parallel()
	s := NewServer(NewBroadcaster(), nil)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d", resp.StatusCode)
	}
}
