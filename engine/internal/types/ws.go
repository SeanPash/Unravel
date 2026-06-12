package types

import "encoding/json"

const (
	MsgTypeGraphUpdate = "graph_update"
	MsgTypeScoreUpdate = "score_update"
	MsgTypeChainResult = "chain_result"
	MsgTypeNarration   = "narration"
	MsgTypeLogEvent    = "log_event"
	MsgTypeThreatIntel = "threat_intel"
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
	EventID       string  `json:"event_id"`
	Description   string  `json:"description"`
	Confidence    float64 `json:"confidence"`
	TS            int64   `json:"ts"`
	TechniqueID   string  `json:"technique_id,omitempty"`
	TechniqueName string  `json:"technique_name,omitempty"`
	Tactic        string  `json:"tactic,omitempty"`
}

type ChainResultPayload struct {
	IncidentID    string      `json:"incident_id,omitempty"`
	IncidentLabel string      `json:"incident_label,omitempty"`
	Confidence    float64     `json:"confidence"`
	Steps         []ChainStep `json:"steps"`
	Tactics       []string    `json:"tactics,omitempty"`
}

// NarrationPhase is the AI's prose for one attack phase. Only the id, title,
// and summary come from the model; everything structural about a phase
// (nodes, edges, timestamps, confidence) is derived from the chain by the
// UI so the model cannot hallucinate graph references.
type NarrationPhase struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Summary string `json:"summary"`
}

type NarrationPayload struct {
	IncidentID string           `json:"incident_id,omitempty"`
	Text       string           `json:"text"`
	Hypotheses []string         `json:"hypotheses"`
	Actions    []string         `json:"actions"`
	Phases     []NarrationPhase `json:"phases,omitempty"`
}

// LogEventPayload carries the raw Splunk event behind a graph edge so the UI
// can show source log evidence. EventID matches the edge's source_event_id.
type LogEventPayload struct {
	EventID string         `json:"event_id"`
	TS      int64          `json:"ts"`
	Source  string         `json:"source"`
	Raw     map[string]any `json:"raw"`
}

// ThreatIntelPayload is the threat-intel agent's enrichment of a chain. Status
// is "ok" or "error". Techniques are deduplicated by technique ID.
type ThreatIntelPayload struct {
	IncidentID string                 `json:"incident_id,omitempty"`
	Status     string                 `json:"status"`
	Summary    string                 `json:"summary"`
	Techniques []ThreatIntelTechnique `json:"techniques"`
	CVEMatches []CVEMatch             `json:"cve_matches,omitempty"`
}

type ThreatIntelTechnique struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Groups      []string `json:"groups"`
	Software    []string `json:"software"`
	Mitigations []string `json:"mitigations"`
}

type CVEMatch struct {
	ID       string `json:"id"`
	Summary  string `json:"summary"`
	InKEV    bool   `json:"in_kev"`
	Severity string `json:"severity,omitempty"`
}

func NewMessage(msgType string, payload any) (WSMessage, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return WSMessage{}, err
	}
	return WSMessage{Type: msgType, Payload: raw}, nil
}
