# Engine Spec - Luigi

Owner: luigi
Scope: Go engine binary - all 7 subcomponents, WebSocket server, operating modes, persistence

---

## Repository Layout

```
engine/
├── cmd/engine/main.go          binary entry point, flag parsing, mode dispatch
├── internal/
│   ├── types/                  shared structs: events, nodes, edges, WS envelope
│   ├── schema/                 per-source parsers (sysmon.go, winsec.go, adaudit.go)
│   ├── graph/                  incremental in-memory adjacency + BadgerDB snapshots
│   ├── scorer/                 online suspicion scorer
│   ├── chain/                  backward-walk chain extractor
│   ├── splunk/                 Source interface + MockSource + RESTSource
│   ├── ai/                     Narrator interface + ClaudeNarrator
│   ├── api/                    HTTP server, WebSocket upgrade, broadcaster
│   └── pipeline/               wires everything into the streaming loop
├── docs/adr/                   architecture decision records
├── testdata/                   canned event timelines for replay and unit tests
└── e2e_test.go                 end-to-end smoke test
```

---

## Package Responsibilities

### `types`

Defines all shared data types. No logic, no I/O.

- Typed event structs: `ProcessCreate`, `NetworkConnect`, `Auth`, `ADEvent`
- Graph node types: `Process`, `Host`, `User`, `NetFlow`
- Graph edge types: `spawned`, `connected_to`, `authenticated_as`, `accessed_credential`, `dumped_memory_of`, `read_file`
- Edge carries: `(id, src, dst, kind, timestamp, confidence, source_event_id)`
- WebSocket message envelope: `{ type string, payload json.RawMessage }`
- Payload structs for each message type (see WebSocket schema below)

### `schema`

One file per log source. Each parser takes a raw `map[string]any` (deserialized Splunk JSON) and returns a typed event or an error.

- `sysmon.go`: EID 1 (ProcessCreate), EID 3 (NetworkConnect), EID 10 (ProcessAccess), EID 11 (FileCreate)
- `winsec.go`: 4624/4625 (logon/failure), 4672 (special logon), 4768/4769 (Kerberos TGT/service ticket)
- `adaudit.go`: domain controller object changes

### `graph`

Incremental in-memory adjacency structure. Optimized for causal queries on streaming inputs, not relational lookups.

- `FindOrCreateNode(kind, key string) *Node` - idempotent; returns existing node or creates it
- `AppendEdge(src, dst *Node, kind EdgeKind, ts time.Time, confidence float64, srcEventID string) *Edge`
- `Snapshot() GraphSnapshot` - deep copy for broadcasting to the UI
- Periodic goroutine flushes snapshots to BadgerDB for crash recovery
- Separate `TemporalIndex`: time-bucketed adjacency answering "what edges touched node X in window [t1, t2]" in O(log n)

### `scorer`

Online suspicion scoring. Updates incrementally as each new edge arrives; never rescans history.

Three scoring terms (full MVP):

1. **Frequency-rarity**: unigram model over `(parent_image, child_image)` and `(src_role, dst_role, auth_kind)` tuples. Rare combinations score high. Maintained as a count map; score = 1 / log(1 + count).
2. **Temporal decay**: edges close in time on the same causal chain reinforce; gaps longer than a configurable window decay exponentially.
3. **Structural lift**: multiplier applied when a chain crosses a host boundary or touches a sensitive node (DC, lsass, domain admin credential).

`ScoreEdge(e *Edge, g *Graph) float64` - returns composite score, updates internal state.

Threshold: when any connected subgraph's mean edge score exceeds the configurable trigger threshold, emits a signal to the chain extractor.

### `chain`

Triggered by the scorer's threshold signal.

- `Extract(g *Graph, hotNode *Node) ChainResult`
- Runs a weighted backward walk from the highest-scored node
- Returns an ordered `[]ChainStep`, each carrying `(event_id, description, confidence, timestamp)`
- Also returns an overall chain confidence (geometric mean of step confidences)

### `splunk`

```go
type Source interface {
    Events() <-chan RawEvent
    Close() error
}
```

Two implementations:

- `MockSource`: reads `testdata/*.json` files, emits events at configurable speed. Used in all tests and replay mode.
- `RESTSource`: long-running HTTP connection to Splunk `services/search/jobs/export` with `output_mode=json`. Reconnects on drop with exponential backoff.

### `ai`

```go
type Narrator interface {
    Narrate(ctx context.Context, chain ChainResult) (Narration, error)
}
```

- `StubNarrator`: returns a canned narration. Used when `--mode=ai-off`.
- `ClaudeNarrator`: sends `ChainResult` as structured JSON to Claude Sonnet 4.6. Uses prompt caching on a static system prompt that embeds the engine output schema. Returns `Narration{ Text, Hypotheses []string, Actions []string }`.

### `api`

- HTTP server on a configurable port (default: `8080`, override with `--port`)
- `GET /` serves the React static build (embedded via `go:embed`)
- `GET /ws` upgrades to WebSocket
- `Broadcaster`: fan-out to all connected clients. Non-blocking send; slow clients are dropped rather than blocking the pipeline.

### `pipeline`

Wires all packages into the streaming loop:

```
Source.Events()
  -> schema mapper (per-source dispatch)
  -> graph.AppendEdge
  -> scorer.ScoreEdge  -- triggers chain.Extract on threshold
  -> ai.Narrator.Narrate
  -> api.Broadcaster.Send
```

Runs as a single goroutine reading from the source channel. Scorer threshold check and chain extraction happen synchronously in the loop; narration call is dispatched to a goroutine with a timeout so a slow LLM response never stalls ingest.

---

## Operating Modes

Controlled by `--mode` flag on the binary:

| Mode | Source | Narrator |
|---|---|---|
| `live` (default) | `RESTSource` against real Splunk | `ClaudeNarrator` |
| `replay` | `MockSource` reading `testdata/` | `ClaudeNarrator` |
| `ai-off` | `RESTSource` or `MockSource` | `StubNarrator` |

`--replay-speed=1.0` scales event timestamps during replay (2.0 = double speed, 0.1 = slow-motion).

---

## WebSocket Message Schema

Luigi publishes. Sean consumes. This schema is the integration contract - do not change it without coordinating with Sean.

All messages share the envelope:

```json
{ "type": "<message_type>", "payload": { ... } }
```

### `graph_update`

Sent after every edge append. Contains only the new or changed nodes and edges (incremental, not full graph).

```json
{
  "type": "graph_update",
  "payload": {
    "nodes": [
      { "id": "proc-1234", "kind": "Process", "label": "powershell.exe", "attrs": { "pid": 1234, "host": "WS01", "ts": 1749100000 } }
    ],
    "edges": [
      { "id": "edge-abc", "src": "proc-5678", "dst": "proc-1234", "kind": "spawned", "ts": 1749100000, "confidence": 0.72 }
    ]
  }
}
```

### `score_update`

Sent when the scorer updates a previously-emitted edge's score.

```json
{
  "type": "score_update",
  "payload": { "edge_id": "edge-abc", "score": 0.87 }
}
```

### `chain_result`

Sent when the chain extractor fires.

```json
{
  "type": "chain_result",
  "payload": {
    "confidence": 0.91,
    "steps": [
      { "event_id": "evt-001", "description": "cmd.exe spawned powershell.exe", "confidence": 0.95, "ts": 1749100000 },
      { "event_id": "evt-002", "description": "powershell.exe accessed lsass.exe", "confidence": 0.88, "ts": 1749100010 }
    ]
  }
}
```

### `narration`

Sent after the AI narrator returns.

```json
{
  "type": "narration",
  "payload": {
    "text": "A macro-enabled document spawned PowerShell, which accessed LSASS to dump credentials...",
    "hypotheses": ["Credential material may have been exfiltrated before network telemetry began"],
    "actions": ["Isolate WS01", "Reset credentials for affected accounts", "Search for lateral movement from WS01"]
  }
}
```

---

## Test Strategy

- Unit tests live next to the package they test (`graph/graph_test.go`, `scorer/scorer_test.go`, etc.)
- `testdata/chain-phishing.json`: canned 5-step kill chain event sequence used by e2e and replay tests
- `e2e_test.go` at the module root: wires `MockSource` + `StubNarrator` through the full pipeline, connects a WebSocket client, asserts that a `chain_result` message is received with confidence > 0.8

Run with: `go test ./...` from `engine/`

---

## Full MVP Task Checklist

### Foundation

- [ ] Initialize Go module (`engine/go.mod`)
- [ ] Define all types in `internal/types` (events, nodes, edges, WS envelope, payload structs)

### Schema mapper

- [ ] `schema/sysmon.go`: EID 1, 3, 10, 11 parsers
- [ ] `schema/winsec.go`: 4624, 4625, 4672, 4768, 4769 parsers
- [ ] `schema/adaudit.go`: domain object change parser
- [ ] Unit tests for each parser against raw fixture JSON

### Graph

- [ ] `graph/graph.go`: in-memory adjacency, `FindOrCreateNode`, `AppendEdge`, `Snapshot`
- [ ] `graph/temporal.go`: time-bucketed temporal index
- [ ] `graph/persist.go`: BadgerDB snapshot goroutine
- [ ] Unit tests: node idempotency, edge append, temporal query

### Scorer

- [ ] `scorer/scorer.go`: frequency-rarity unigram
- [ ] `scorer/scorer.go`: temporal decay term
- [ ] `scorer/scorer.go`: structural lift multiplier
- [ ] `scorer/scorer.go`: threshold trigger signal
- [ ] Unit tests: each scoring term in isolation, composite score on fixture chain

### Chain extractor

- [ ] `chain/chain.go`: backward walk implementation
- [ ] Unit tests: correct path on fixture graph, confidence calculation

### Splunk source

- [ ] `splunk/mock.go`: `MockSource` reading testdata JSON
- [ ] `splunk/rest.go`: `RESTSource` with reconnect backoff
- [ ] Integration test: `RESTSource` against a local Splunk instance (manual, not CI)

### AI narrator

- [ ] `ai/stub.go`: `StubNarrator` with canned output
- [ ] `ai/claude.go`: `ClaudeNarrator` with prompt caching
- [ ] Unit test: `ClaudeNarrator` with a mocked HTTP transport

### API and WebSocket

- [ ] `api/server.go`: HTTP server, static file embed, WebSocket upgrade
- [ ] `api/broadcaster.go`: fan-out broadcaster, non-blocking send
- [ ] Unit tests: broadcaster drop-slow-client behavior

### Pipeline and binary

- [ ] `pipeline/pipeline.go`: streaming loop wiring all packages
- [ ] `cmd/engine/main.go`: flag parsing, mode dispatch, graceful shutdown
- [ ] `e2e_test.go`: full pipeline smoke test with `MockSource` + `StubNarrator`

### Testdata

- [ ] `testdata/chain-phishing.json`: 5-step kill chain event sequence (Sysmon + WinSec + AD)

---

# CURRENT TASKS (post-MVP) - START HERE

> **For new Claude sessions:** the MVP checklist above is complete. The phase-1 walking skeleton shipped. Pick up from this section. These tasks are scoped to Luigi (engine binary, Splunk integration, repo-root deliverables) and must be done before the hackathon submission.

Status snapshot (as of 2026-06-06): all seven engine subcomponents are implemented and tested, `go test ./...` is green, and the replay pipeline works end-to-end through the WebSocket. See `CLAUDE.md` section `Engine State` for the per-package summary. The work below closes the gap between "engine works in isolation" and "hackathon-ready submission."

## L1. Embed the UI build into the engine binary

**Why:** Right now `cmd/engine/main.go` passes `nil` for `api.NewServer`'s static FS, so the React app must be served separately (Vite). For the demo and submission we want one binary that serves the WebSocket and the UI on the same port.

**Where:** `engine/cmd/engine/main.go`, plus a new `engine/internal/api/static.go` (or similar) holding the `go:embed` directive.

- [ ] Add a build step (Makefile target, `go generate` directive, or short shell script in `engine/`) that runs `npm --prefix ../ui run build` and copies `ui/dist/` into `engine/internal/api/static/`. Commit a `.gitignore` entry for the copied tree so the build output is not checked in.
- [ ] Create `engine/internal/api/static.go` with `//go:embed static/*` exposing an `fs.FS`. If the embed directory is empty during `go build` it must not fail; gate the embed behind a build tag or commit a `.gitkeep` so the empty case still compiles.
- [ ] In `cmd/engine/main.go`, replace `api.NewServer(bcast, nil)` with the embedded FS. Strip the leading `static/` prefix via `fs.Sub` so `GET /` serves `index.html`.
- [ ] Smoke test: from `engine/`, run the build step, then `go run ./cmd/engine --mode=replay`. Open `http://localhost:8080/` in a browser. The React UI must load and connect to `/ws` without setting `VITE_WS_URL`.
- [ ] Update the `Build, Test, Run` section of `CLAUDE.md` with the build step.

## L2. Splunk HEC write-back

**Why:** The locked design decision in `CLAUDE.md` calls for HEC write-back of engine-derived events (chain results, scored edges) so a Splunk analyst can pivot from the engine's output back into raw logs. Without it, the "writes back to Splunk" judging story is unsupported. The replay demo does not require it, but the hackathon submission does.

**Where:** new package `engine/internal/splunk/hec.go` (plus tests) and pipeline wiring.

- [ ] Define `type HECClient` with `Send(ctx context.Context, event any) error`. Use `services/collector/event` with an `Authorization: Splunk <token>` header and `index=` plus `sourcetype=` configurable.
- [ ] Add a `HECConfig` struct (URL, token, index, sourcetype, insecure) and a constructor.
- [ ] Wire HEC into `pipeline.Pipeline` as an optional sink: on every `chain_result`, send a structured JSON event. Make it nil-safe so replay and ai-off modes still work without HEC configured.
- [ ] Add CLI flags to `cmd/engine/main.go`: `--hec-url`, `--hec-token`, `--hec-index`, `--hec-sourcetype`. Default to disabled when token is empty.
- [ ] Unit test against an `httptest.Server` that asserts the request shape and auth header.
- [ ] Document the flags in `CLAUDE.md`'s `Build, Test, Run` section.

## L3. Repo-root README, LICENSE, architecture diagram

**Why:** Explicit hackathon submission requirements (see `causal-reconstruction-engine.md`).

- [ ] `README.md` at repo root. Sections: one-paragraph project pitch, architecture overview (link to the diagram), replay quickstart (`go run ./cmd/engine --mode=replay` from `engine/` plus a pointer to the UI), live mode quickstart, repo layout pointers (engine, ui, lab, spec, docs), license note. Keep it tight; this is the file judges open first.
- [ ] `LICENSE` at repo root. MIT or Apache-2.0. Confirm with the team before committing.
- [ ] `architecture.svg` (or `.png`) at repo root. Must show: Splunk REST tail -> schema mapper -> graph builder -> temporal index -> scorer -> chain extractor -> AI narrator -> WebSocket -> UI. Label the AI narrator as the only LLM-touching component to reinforce the architectural north star. Reference it from the README and from the new docs in CLAUDE.md.

## Definition of done for this task group

- [ ] `go run ./cmd/engine --mode=replay` from a fresh clone (after `npm install && npm run build` in `ui/`, plus the embed build step) boots a single process at `:8080` that serves the UI and streams the replay timeline.
- [ ] HEC write-back is verified against a local Splunk instance (or the lab one if L4 from Sean is done first); the engine pushes at least one `chain_result` event per replay run.
- [ ] The repo root contains `README.md`, `LICENSE`, and `architecture.svg` (or `.png`).
- [ ] `CLAUDE.md` is updated to reflect the new build step, HEC flags, and removed entries from the `Outstanding Work` list.
