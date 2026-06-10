package types

import "encoding/json"

const (
	MsgTypeGraphUpdate = "graph_update"
	MsgTypeScoreUpdate = "score_update"
	MsgTypeChainResult = "chain_result"
	MsgTypeNarration   = "narration"
	MsgTypeLogEvent    = "log_event"
)

type WSMessage struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

type GraphUpdatePayload struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

type ScoreUpdatePayload struct {
	EdgeID string  `json:"edge_id"`
	Score  float64 `json:"score"`
}

type ChainStep struct {
	EventID     string  `json:"event_id"`
	Description string  `json:"description"`
	Confidence  float64 `json:"confidence"`
	TS          int64   `json:"ts"`
}

type ChainResultPayload struct {
	Confidence float64     `json:"confidence"`
	Steps      []ChainStep `json:"steps"`
}

type NarrationPayload struct {
	Text       string   `json:"text"`
	Hypotheses []string `json:"hypotheses"`
	Actions    []string `json:"actions"`
}

// LogEventPayload carries the raw Splunk event behind a graph edge so the UI
// can show source log evidence. EventID matches the edge's source_event_id.
type LogEventPayload struct {
	EventID string         `json:"event_id"`
	TS      int64          `json:"ts"`
	Source  string         `json:"source"`
	Raw     map[string]any `json:"raw"`
}

func NewMessage(msgType string, payload any) (WSMessage, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return WSMessage{}, err
	}
	return WSMessage{Type: msgType, Payload: raw}, nil
}
