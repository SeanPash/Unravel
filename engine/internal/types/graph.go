package types

type NodeKind string

const (
	NodeKindProcess NodeKind = "Process"
	NodeKindHost    NodeKind = "Host"
	NodeKindUser    NodeKind = "User"
	NodeKindNetFlow NodeKind = "NetFlow"
)

type EdgeKind string

const (
	EdgeKindSpawned            EdgeKind = "spawned"
	EdgeKindConnectedTo        EdgeKind = "connected_to"
	EdgeKindAuthenticatedAs    EdgeKind = "authenticated_as"
	EdgeKindAccessedCredential EdgeKind = "accessed_credential"
	EdgeKindDumpedMemoryOf     EdgeKind = "dumped_memory_of"
	EdgeKindReadFile           EdgeKind = "read_file"
)

type Node struct {
	ID    string         `json:"id"`
	Kind  NodeKind       `json:"kind"`
	Label string         `json:"label"`
	Attrs map[string]any `json:"attrs"`
}

type Edge struct {
	ID            string   `json:"id"`
	Src           string   `json:"src"`
	Dst           string   `json:"dst"`
	Kind          EdgeKind `json:"kind"`
	TS            int64    `json:"ts"`
	Confidence    float64  `json:"confidence"`
	SourceEventID string   `json:"source_event_id,omitempty"`
}
