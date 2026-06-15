# Unravel - Submission

Unravel is a causal reconstruction engine. It rebuilds an attack chain from Splunk telemetry while the attack is still happening, and tells the analyst what happened, why it matters, and what to do about it.

## The problem it solves

A single Splunk alert (say, PowerShell running on a workstation) tells you almost nothing on its own. To find out whether it matters, an analyst pivots by hand: what spawned that PowerShell, did it touch credentials, did anything authenticate off the host afterward, did that reach the Domain Controller. The answers already sit in Splunk, scattered across Sysmon, Windows Security, and Active Directory audit logs. Stitching them into one story takes 30+ minutes per alert, and the intruder keeps moving the whole time.

Unravel does that stitching continuously. Events stream out of Splunk, the engine grows a typed provenance graph in memory, scores every new edge against a learned baseline, and the moment a connected cluster crosses a threshold it walks backward to recover the single most suspicious causal path.

## What it reconstructs

The demo scenario runs a full intrusion from first contact to domain compromise:

1. A macro-enabled document arrives by phishing (T1566.001)
2. The macro spawns PowerShell (T1059.001)
3. PowerShell reads LSASS memory and dumps credentials (T1003.001)
4. A stolen ticket authenticates to the Domain Controller (T1550.003, pass-the-ticket)
5. A domain-admin session opens on the DC (T1078.002)

As each step fires, the suspicion score climbs and the causal graph assembles itself in the browser in real time. Every extracted step picks up its MITRE ATT&CK technique and tactic from deterministic rules, not from a model.

## How it works

The engine is seven stages. Six are pure Go and never call a model:

- **Ingest** tails Splunk's `services/search/jobs/export` endpoint over a long-lived REST stream, with exponential-backoff reconnect.
- **Schema mapper** turns raw Splunk events into typed Go structs, with per-source parsers for Sysmon (EID 1/3/10/11), Windows Security (4624/4625/4672/4768/4769), and AD audit.
- **Graph builder** finds-or-creates Process, Host, User, and NetFlow nodes and appends typed edges (spawned, accessed_credential, dumped_memory_of, authenticated_as), each carrying a timestamp, confidence, and source event ID.
- **Temporal index** buckets edges by minute, so "which edges touched node X in this window" answers in logarithmic time.
- **Suspicion scorer** combines frequency-rarity (rare parent/child and auth tuples score high), exponential temporal decay, and structural lift for crossing host boundaries or touching sensitive nodes like lsass.exe. It updates incrementally and assigns stable incident IDs to connected components.
- **Chain extractor** walks backward from the hottest node along the highest-scored edges to recover the most suspicious path, then reverses it into chronological order with per-step confidence.

The seventh stage, the AI narrator, is the only place an LLM touches anything. It turns the extracted chain into a short narrative, missing-evidence hypotheses, and ranked containment actions. The point is that the engine decides what the attack chain is before any model runs. The narrator only ever describes a conclusion the Go code already reached. Run with `--mode=ai-off` and the pipeline still ingests, builds the graph, scores it, and extracts the chain. You lose the English narration and nothing else.

The graph lives in a custom in-memory adjacency structure and snapshots to BadgerDB on a timer. The whole thing ships as one static Go binary with the React UI compiled inside it.

## How it uses Splunk

Three ways:

- **Live ingest** tails the REST export endpoint, reading indexed events as they land.
- **HEC write-back** posts the reconstructed chain back to Splunk as notable events over the HTTP Event Collector, so an analyst can pivot from Unravel's output straight into the raw logs.
- **Splunk MCP Server** routes the narrator's evidence-gathering in live mode. Every SPL query the narrator builds runs through the official server's `splunk_run_query` tool over the MCP streamable-HTTP transport. With MCP on, the narrator also gets a natural-language search tool: it hands a question to the Splunk AI Assistant (`saia_generate_spl`), gets SPL back, and runs that SPL through the MCP server. The activity feed shows both sub-steps.

## How it uses AI

Two agents sit at the seam, both on Google Gemini 3.1 Flash Lite. The narrator receives the extracted chain as structured JSON and can run up to three rounds of tool calls to enrich its own context before it writes a word: process reputation, account logon history, and raw events behind specific event IDs. Each tool builds and runs a real SPL query. The threat-intel agent enriches the chain's techniques against live external sources through its own tool calls: MITRE ATT&CK, CISA Known Exploited Vulnerabilities, and NVD, returning matched techniques and CVEs with KEV and severity flags.

Drop every API key and the narrator falls back to a deterministic stub and the intel agent to a bundled ATT&CK snapshot, so every tab in the UI still works with zero keys.

## The interface

The front end is React plus Cytoscape.js, embedded in the engine binary. The provenance graph is live: nodes are colored by suspicion and edges appear as Splunk events arrive. When the engine splits activity into distinct incidents, each gets its own labeled region, with a minimap for the whole picture. A time scrubber plays, pauses, and steps through the chain chronologically. One attack-phase card per MITRE tactic carries the AI's summary, confidence, and technique IDs, and clicking a card drives the camera, timeline, and logs to that phase. Pinnable node drawers explain a node's role, its phases and techniques, and its parent/child relationships, with separate panels for the raw Splunk events behind any node and the enriched ATT&CK/CVE context for the chain.

## Running it

Three modes. `replay` feeds a canned kill chain through the full pipeline with no Splunk needed. `ai-off` does the same but skips every model call, so the engine carries the demo on its own. `live` streams from a real Splunk instance over the REST export endpoint. From `engine/`, `make release` builds the UI into the binary and `./unravel --mode=replay` runs the demo at http://localhost:8080.

Built for the Splunk Agentic Ops Hackathon, Security track, by Luigi Fernandez and Sean Pashaev. MIT licensed.
