package types

import "encoding/json"

const (
	MsgTypeGraphUpdate   = "graph_update"
	MsgTypeScoreUpdate   = "score_update"
	MsgTypeChainResult   = "chain_result"
	MsgTypeNarration     = "narration"
	MsgTypeLogEvent      = "log_event"
	MsgTypeThreatIntel   = "threat_intel"
	MsgTypeAgentActivity = "agent_activity"
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

// AgentActivityPayload is one step in an AI agent's tool-use loop, streamed to
// the UI as it happens so the analyst can watch the narrator and threat-intel
// agent gather and cross-reference evidence in real time. It is purely
// observational: emitting it never changes engine output. Kind is the lifecycle
// stage of the step; Source names the real data source consulted so the feed
// stays honest (e.g. local Splunk vs. an external catalog).
type AgentActivityPayload struct {
	IncidentID string `json:"incident_id,omitempty"`
	// Agent is "narrator" or "intel".
	Agent string `json:"agent"`
	// Seq orders steps within one agent run for a single incident.
	Seq int `json:"seq"`
	// Kind is "thinking" | "tool_call" | "tool_result" | "done" | "error".
	Kind string `json:"kind"`
	// Tool is the tool name for tool_call/tool_result steps, else empty.
	Tool string `json:"tool,omitempty"`
	// Source is the human-readable origin of the data, e.g. "Splunk threat_intel
	// index", "CISA KEV", "NVD", "MITRE ATT&CK".
	Source string `json:"source,omitempty"`
	// Label is a one-line human sentence describing the step.
	Label string `json:"label"`
	// Detail is a short result summary for tool_result steps.
	Detail string `json:"detail,omitempty"`
	// Status is "ok" | "empty" | "error" for tool_result steps.
	Status string `json:"status,omitempty"`
	// TS is the wall-clock unix time the step was emitted (stamped by the pipeline).
	TS int64 `json:"ts,omitempty"`
}

func NewMessage(msgType string, payload any) (WSMessage, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return WSMessage{}, err
	}
	return WSMessage{Type: msgType, Payload: raw}, nil
}
