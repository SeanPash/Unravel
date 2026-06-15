# Causal Reconstruction Engine

A live, streaming provenance-graph engine for security incident investigation. Consumes endpoint and identity telemetry from Splunk, reconstructs the causal chain of an active attack as it unfolds, and surfaces the maximally suspicious path with a plain-English narration.

Built for the Splunk Agentic Ops Hackathon (Security track). The thesis is **engine first, AI second**: a custom Go engine does the structural work (ingest, schema mapping, graph construction, scoring, chain extraction) and a single LLM call at the end narrates the result. Turn off the LLM and the engine still produces a reconstructed attack chain.

## Problem

A SOC analyst gets a Splunk alert that PowerShell ran on a workstation. The analyst then spends 30+ minutes pivoting through Splunk searches to answer: what spawned this process, did it touch credentials, did anything authenticate off the host afterwards, did that auth land on the Domain Controller? The information is all in Splunk, but reconstructing the causal chain across event sources is manual, slow, and error-prone.

This engine performs that reconstruction continuously and incrementally. As events stream in from Splunk, it grows a typed provenance graph in memory, scores edges for suspicion against a learned baseline, and when a connected subgraph crosses a threshold it extracts the most suspicious causal path and ships it to the UI with narration.

## Demonstrated Attack Chain

A canonical enterprise kill chain runs end-to-end inside a virtualized Active Directory lab:

1. Phishing email delivers a macro-enabled document
2. Macro execution spawns PowerShell
3. PowerShell accesses LSASS to dump credentials
4. Dumped credentials authenticate to the Domain Controller via Kerberos
5. Domain Controller compromise

The engine reconstructs this chain live, with the audience watching the suspicion score climb and the causal graph form.

## Architecture

Seven subcomponents. Six are pure Go with zero LLM calls. The seventh is the only seam where an LLM is allowed.

```
Virtualized AD lab (GOAD-based)
        |
        |  Splunk Universal Forwarder on each host
        v
Splunk Enterprise (indexed events)
        |
        |  REST streaming export (tail mode)
        v
+-------------------------------------------------------+
| Causal Reconstruction Engine (Go)                     |
|                                                       |
|  1. Ingest layer        REST tail to envelope         |
|  2. Schema mapper       typed events per source       |
|  3. Graph builder       incremental, in-memory        |
|  4. Temporal index      time-bucketed lookups         |
|  5. Suspicion scorer    frequency x decay x lift      |
|  6. Chain extractor     max-suspicion backward walk   |
|  7. AI narrator         chain to English + hypotheses |
|                                                       |
+-------------------------------------------------------+
        |
        |  WebSocket
        v
React + Cytoscape.js UI
        - Live force-directed provenance graph
        - Time scrubber
        - Narration and missing-evidence panel
```

### Subcomponent Roles

1. **Ingest layer.** Tails Splunk's `services/search/jobs/export` endpoint with a long-running SPL search. Buffers and back-pressures into the schema mapper.
2. **Schema mapper.** Per-source parsers turn raw events into typed Go structs (`ProcessCreate`, `Auth`, `NetworkConnect`, etc.). Normalizes Sysmon quirks.
3. **Provenance graph builder.** On each typed event: find-or-create entity nodes (`Process`, `Host`, `User`, `NetFlow`), append typed edges (`spawned`, `connected_to`, `authenticated_as`, `accessed_credential`, `dumped_memory_of`, `read_file`). Edges carry `(timestamp, confidence, source_event_id)`.
4. **Temporal causal index.** Time-bucketed adjacency: "what edges touched node X in window [t1, t2]" in O(log n). Tuned for causal queries, not relational lookups.
5. **Online suspicion scorer.** Three terms:
   - Frequency-rarity: unigram model over `(parent_image, child_image)` and `(src_role, dst_role, auth_kind)` tuples. Rare combinations score high.
   - Temporal decay: edges close in time on the same causal chain reinforce; long gaps decay exponentially.
   - Structural lift: chains crossing host boundaries or touching sensitive nodes (DC, lsass) get a multiplier.
   Updates incrementally as new edges arrive.
6. **Chain extractor.** When a connected subgraph crosses the suspicion threshold, runs a weighted backward walk from the highest-scored node to recover the maximally suspicious causal path. Output is an ordered list of events with per-step confidence.
7. **AI narrator.** Sends the extracted chain (structured JSON) to Gemini 3.1 Flash Lite with a fixed system instruction and a static engine-output schema preamble that benefits from implicit context caching. Before narrating, it can issue agentic tool calls (up to 3 rounds) to enrich the chain - `lookup_process_reputation`, `get_account_logon_history`, `fetch_raw_events` - each of which builds an SPL query and runs it through a Splunk searcher. Returns plain-English narration, missing-evidence hypotheses, and a ranked list of containment actions.

### The AI Seam

The LLM is the last hop only. Structured engine output goes in; structured natural-language output comes out. The narrator may issue Splunk tool calls to gather more context for itself, but that is still inside the seam: it is the narrator enriching its own input, not the engine calling an LLM. Nothing in ingest, graph construction, scoring, or chain extraction touches an LLM. The engine ships with an AI-off mode that proves it: the pipeline runs end-to-end and produces a reconstructed chain without any narration call.

## Tech Stack

| Layer | Choice | Reason |
|---|---|---|
| Engine language | Go 1.25+ | Strong concurrency for streaming, static binary, readable to judges, no GIL. |
| Graph store | Custom in-memory adjacency, periodic snapshot to BadgerDB | The graph engine is the project. Judges read our data structures, not Neo4j calls. |
| Splunk ingest | REST `services/search/jobs/export` (tail mode) | Splunk-native, no Kafka, demonstrates platform fluency. |
| Splunk write-back | HEC | Engine findings flow back to Splunk as notable events. |
| WebSocket library | `github.com/gorilla/websocket` | Mature, widely used, simple upgrade/read/write API. |
| UI framework | React 18 + Vite + TypeScript | Fast iteration, strong type safety, easy to test. |
| Graph visualisation | Cytoscape.js | Mature, animates well, fits the 3-minute demo. |
| AI model | Gemini 3.1 Flash Lite (Google) | Cost/latency profile suits ~3 call-sites per investigation; static schema preamble benefits from implicit context caching. |
| Virtualized lab | GOAD (Game of Active Directory) | Ready-made multi-VM AD lab, purpose-built for this exact scenario. |
| Attack runner | Python + Atomic Red Team atomics on a timer | Predictable, reproducible for demo recording. |
| Test runner | `go test` and `vitest` | Standard tooling, no novel test infrastructure. |

## MVP Scope

| Dimension | Phase 1 (walking skeleton) | Full MVP |
|---|---|---|
| Event types | Sysmon EID 1 (ProcessCreate) | Sysmon EID 1, 3, 10, 11; Windows Security 4624/4625/4672/4768/4769; AD audit |
| Node types | Process | Process, Host, User, NetFlow |
| Edge types | spawned | spawned, connected_to, authenticated_as, accessed_credential, dumped_memory_of, read_file |
| Scoring | Frequency-rarity unigram | Frequency-rarity x temporal decay x structural lift |
| AI narrator | Stub (canned output) | Gemini 3.1 Flash Lite, 3 call-sites |
| Splunk source | Mock (in-process) | Real REST tail client |
| Persistence | In-memory only | In-memory + periodic BadgerDB snapshot |
| Containment action | None | Splunk notable + stubbed EDR isolate API |

Phase 1 exists to prove the architecture end-to-end with a single vertical slice. Each axis above can be extended independently in later phases.

## Repository Layout

```
.
├── README.md                         project readme + quickstarts
├── architecture.svg                  architecture diagram (README requirement)
├── causal-reconstruction-engine.md   this file
├── LICENSE                           MIT
├── spec/                             canonical implementation specs (luigi-engine, sean-ui-lab)
├── docs/superpowers/                 feature design docs + execution plans
│
├── engine/                           Go module
│   ├── cmd/engine/                   binary entry point, flag parsing, mode dispatch
│   ├── internal/
│   │   ├── types/                    shared data types (events, nodes, edges, WS envelope)
│   │   ├── schema/                   per-source event parsers (sysmon, winsec, adaudit)
│   │   ├── graph/                    incremental adjacency, temporal index, BadgerDB persist
│   │   ├── scorer/                   suspicion scoring
│   │   ├── chain/                    backward-walk chain extractor
│   │   ├── splunk/                   Source + Searcher interfaces (Mock + REST), HEC client
│   │   ├── ai/                       Narrator interface, Gemini client, tool-use, stub
│   │   ├── api/                      HTTP + WebSocket server, broadcaster, embedded static FS
│   │   └── pipeline/                 wires the above into the streaming loop
│   ├── testdata/                     canned event timelines + enrichment fixtures for replay
│   └── e2e_test.go                   end-to-end smoke test
│
├── ui/                               React + Vite + TypeScript app
│   └── src/                          App, GraphView, NarrationPanel, LogsPanel, TimeScrubber, ws
│
└── lab/                              GOAD topology + Splunk forwarders + attack runner
```

## Operating Modes

The engine binary supports several modes to make the architecture inspectable:

- **Live mode.** Streams from a real Splunk instance. Default for the demo.
- **Replay mode.** Loads a canned event timeline from JSON and feeds it through the pipeline at configurable speed. Lets anyone reproduce the demo without standing up Splunk or GOAD.
- **AI-off mode.** Skips the narration call. Pipeline still ingests, builds the graph, scores, and extracts the chain. Demonstrates that the engine produces a reconstructed result without an LLM.

## Non-Goals

Things explicitly out of scope, by design:

- A unified platform combining detection, investigation, and proactive workflows. Investigation is the focus.
- Replacing Splunk for detection. Splunk already does detection well; the engine consumes its output.
- A general-purpose graph database. The in-memory adjacency structure is tuned for causal queries on streaming inputs.
- Machine-learned scoring beyond the unigram baseline. The scoring stays inspectable and explainable for judging.
- Multi-tenant or production hardening. This is a hackathon demo.
- Custom log shippers. Splunk Universal Forwarder handles transport.

## Open Questions

- Exact prompt structure and caching strategy for the three AI call-sites (narrator, missing-evidence hypothesizer, containment suggester).
- GOAD topology slim-down: which VMs to keep for demo-machine performance.
- Containment action behaviour: needs to do something visible on the demo. Likely a Splunk notable plus a fake EDR isolate API.

## References

- `security-track.md` for the full product framing and rationale behind every locked decision.
- `2026-06-04-causal-reconstruction-engine-phase-1.md` for the task-by-task Phase 1 implementation plan.
- `README.md` for hackathon rules and deliverable requirements.
