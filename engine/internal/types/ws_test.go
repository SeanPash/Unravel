package types

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func fixturePath(t *testing.T) string {
	t.Helper()
	// engine/internal/types -> engine/testdata
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Join(wd, "..", "..", "testdata", "chain-phishing.json")
}

func loadFixture(t *testing.T) []WSMessage {
	t.Helper()
	raw, err := os.ReadFile(fixturePath(t))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var msgs []WSMessage
	if err := json.Unmarshal(raw, &msgs); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	return msgs
}

func TestFixture_DecodesIntoTypedPayloads(t *testing.T) {
	msgs := loadFixture(t)
	if len(msgs) == 0 {
		t.Fatal("fixture has no messages")
	}

	saw := map[string]bool{}
	for i, m := range msgs {
		saw[m.Type] = true
		switch m.Type {
		case MsgTypeGraphUpdate:
			var p GraphUpdatePayload
			if err := json.Unmarshal(m.Payload, &p); err != nil {
				t.Fatalf("msg %d graph_update: %v", i, err)
			}
			if len(p.Nodes) == 0 && len(p.Edges) == 0 {
				t.Fatalf("msg %d graph_update: empty nodes and edges", i)
			}
			for _, n := range p.Nodes {
				if n.ID == "" || n.Kind == "" || n.Label == "" {
					t.Fatalf("msg %d node missing required field: %+v", i, n)
				}
			}
			for _, e := range p.Edges {
				if e.ID == "" || e.Src == "" || e.Dst == "" || e.Kind == "" {
					t.Fatalf("msg %d edge missing required field: %+v", i, e)
				}
			}
		case MsgTypeScoreUpdate:
			var p ScoreUpdatePayload
			if err := json.Unmarshal(m.Payload, &p); err != nil {
				t.Fatalf("msg %d score_update: %v", i, err)
			}
			if p.EdgeID == "" {
				t.Fatalf("msg %d score_update missing edge_id", i)
			}
		case MsgTypeChainResult:
			var p ChainResultPayload
			if err := json.Unmarshal(m.Payload, &p); err != nil {
				t.Fatalf("msg %d chain_result: %v", i, err)
			}
			if len(p.Steps) == 0 {
				t.Fatalf("msg %d chain_result has no steps", i)
			}
			for _, s := range p.Steps {
				if s.EventID == "" || s.Description == "" {
					t.Fatalf("msg %d chain step missing field: %+v", i, s)
				}
			}
		case MsgTypeNarration:
			var p NarrationPayload
			if err := json.Unmarshal(m.Payload, &p); err != nil {
				t.Fatalf("msg %d narration: %v", i, err)
			}
			if p.Text == "" {
				t.Fatalf("msg %d narration missing text", i)
			}
		default:
			t.Fatalf("msg %d unknown type: %q", i, m.Type)
		}
	}

	for _, want := range []string{
		MsgTypeGraphUpdate, MsgTypeScoreUpdate, MsgTypeChainResult, MsgTypeNarration,
	} {
		if !saw[want] {
			t.Errorf("fixture missing message type %q", want)
		}
	}
}

func TestNewMessage_RoundTrip(t *testing.T) {
	payload := GraphUpdatePayload{
		Nodes: []Node{{ID: "n1", Kind: NodeKindProcess, Label: "x.exe", Attrs: map[string]any{"pid": 1}}},
		Edges: []Edge{{ID: "e1", Src: "n1", Dst: "n1", Kind: EdgeKindSpawned, TS: 1, Confidence: 0.5}},
	}
	msg, err := NewMessage(MsgTypeGraphUpdate, payload)
	if err != nil {
		t.Fatalf("NewMessage: %v", err)
	}
	if msg.Type != MsgTypeGraphUpdate {
		t.Errorf("type = %q, want %q", msg.Type, MsgTypeGraphUpdate)
	}

	wire, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	var back WSMessage
	if err := json.Unmarshal(wire, &back); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	var got GraphUpdatePayload
	if err := json.Unmarshal(back.Payload, &got); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if len(got.Nodes) != 1 || got.Nodes[0].ID != "n1" {
		t.Errorf("nodes round-trip lost data: %+v", got.Nodes)
	}
	if len(got.Edges) != 1 || got.Edges[0].Kind != EdgeKindSpawned {
		t.Errorf("edges round-trip lost data: %+v", got.Edges)
	}
}
