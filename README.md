# Unravel

**A causal reconstruction engine that rebuilds an attack chain from Splunk telemetry while the attack is still happening.**

![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Go 1.25](https://img.shields.io/badge/go-1.25-00ADD8)
![React 18](https://img.shields.io/badge/react-18-61DAFB)
![Track: Security](https://img.shields.io/badge/track-security-red)

Built for the **Splunk Agentic Ops Hackathon** (Security track).

> **Demo video:** _link added on the submission form before the deadline._

---

## 1. Intro to Unravel

A Splunk alert that PowerShell ran on a workstation tells an analyst little on its own. Answering whether it matters means pivoting by hand: what spawned the process, did it touch credentials, did anything authenticate off the host, did that authentication reach the Domain Controller. The answers are already in Splunk, spread across Sysmon, Windows Security, and Active Directory audit logs, but stitching them into one story takes 30+ minutes per alert while the intruder keeps moving.

Unravel does that stitching continuously. Events stream out of Splunk; the engine grows a typed provenance graph in memory, scores each new edge against a learned baseline, and the moment a connected cluster crosses a threshold it walks backward to recover the single most suspicious causal path. The design is **engine first, AI second**: an LLM enters only at the end, to put that path into plain English. Run `--mode=ai-off` and the pipeline still ingests, builds the graph, scores it, and extracts the chain; only the narration is lost.

It reconstructs a phishing-to-Domain-Controller kill chain:

1. A macro-enabled document arrives by phishing (`T1566.001`)
2. The macro spawns PowerShell (`T1059.001`)
3. PowerShell reads LSASS memory and dumps credentials (`T1003.001`)
4. A stolen ticket authenticates to the Domain Controller (`T1550.003`, pass-the-ticket)
5. A domain-admin session opens on the DC (`T1078.002`)

As each step fires, the suspicion score climbs and the causal graph assembles in the browser. Every extracted step picks up its MITRE ATT&CK technique and tactic from deterministic rules, not from a model.

## 2. Setup and Run Instructions

### Install and run the wizard

```bash
cd engine
make install     # builds the UI + binary and installs unravel to ~/.local/bin
unravel          # first run: a short menu
```

The first run offers two paths. **Connect to my Splunk** asks for your Splunk REST URL, a bearer token (typed without echo), and whether the certificate is self-signed; it checks the connection, saves it to `~/.unravel/config.json`, launches live mode, and opens the UI. **Try the demo** runs the canned kill chain in replay mode with no setup. After the first connect, a bare `unravel` reads the saved config and goes straight to live mode. Run `unravel setup` any time to re-enter the wizard. (Make sure `~/.local/bin` is on your `PATH`.)

### Replay quickstart (no Splunk required)

Replay mode feeds a canned kill chain through the real pipeline.

```bash
cd engine
make release          # builds the React UI, then compiles it into the Go binary
./unravel --mode=replay
```

Open <http://localhost:8080>. The engine replays the phishing-to-DC timeline and streams the graph and narration over WebSocket. Add `GEMINI_API_KEY` to the environment for live narration, or run `--mode=ai-off` to skip the model. With no key, the narrator falls back to a deterministic stub.

To iterate on the UI alone: `cd ui && npm install && npm run mock` starts a standalone WebSocket server that replays a fixture, no engine needed.

### Live mode

```bash
cd engine
./unravel \
  --mode=live \
  --splunk-url=https://<splunk-host>:8089 \
  --splunk-token=<token> \
  --splunk-search="search index=sysmon" \
  --gemini-key=$GEMINI_API_KEY \
  --hec-url=https://<splunk-host>:8088 \
  --hec-token=<hec-token> \
  --insecure
```

Any explicit flag (including `--mode`) runs the engine directly and bypasses the wizard. To route the narrator's Splunk enrichment through the official Splunk MCP Server instead of REST, add `--splunk-mcp-url` and `--splunk-mcp-token` (the MCP token is a separate per-app encrypted credential, not `--splunk-token`). `--splunk-insecure` (deprecated alias `--insecure`) skips TLS verification for self-signed certs; the `--hec-*` flags are optional and disable write-back when omitted.

### Windows scripts

Windows needs no `make`. The scripts live in `engine/` and need only `go` and `npm`.

```powershell
cd engine
.\run.cmd                # zero-install: builds in place on first run, then runs the replay demo
.\install.cmd            # builds + installs unravel to %LOCALAPPDATA%\Unravel and adds it to PATH
```

In PowerShell the `.\` prefix is required; from `cmd.exe` the bare name works. Pass `rebuild` to either script to force a fresh build. `install.cmd` adds the install directory to your user PATH, so open a new terminal before `unravel` resolves by name. To bake a Gemini key into the binary, build with `powershell -ExecutionPolicy Bypass -File .\build.ps1 -Install`; it is the only build path that reads `engine/gemini.key`.

### Flags

`./unravel --help` prints the full flag list compiled into your binary and is the source of truth. The most useful flags:

| Flag | Default | What it does |
|------|---------|--------------|
| `--mode` | `replay` | Engine mode: `live`, `replay`, or `ai-off` |
| `--port` | `8080` | HTTP/WebSocket listen port |
| `--splunk-url` | `https://localhost:8089` | Splunk REST base URL (live mode) |
| `--splunk-token` | empty | Splunk bearer token (env `SPLUNK_TOKEN`; required in live mode) |
| `--splunk-search` | `search index=sysmon` | SPL search expression to tail (live mode) |
| `--gemini-key` | empty | Google Gemini API key (env `GEMINI_API_KEY`); omit for the stub narrator |
| `--hec-url` | empty | Splunk HEC base URL for chain-result write-back; empty disables it |
| `--splunk-insecure` | `false` | Skip TLS verification for Splunk REST/HEC/MCP (deprecated alias `--insecure`) |

## 3. Required Dependencies

- **Go 1.25+** and **Node 20+** to build the engine and UI.
- Windows needs no `make`; use the `.cmd` / `.ps1` scripts in `engine/`.
- **Gemini API key (optional).** Without one, narration falls back to a deterministic stub and the threat-intel agent to a bundled ATT&CK snapshot, so every UI tab still works with zero keys.
- **NVD API key (optional, `--nvd-key`).** Lifts the CVE rate limit for live threat-intel enrichment.

## 4. Example Configuration or Datasets

**Saved config.** The wizard's **Connect to my Splunk** path writes `~/.unravel/config.json` (file mode `0600`) holding the Splunk REST URL, bearer token, and self-signed flag. A later bare `unravel` reads it and launches live mode directly.

**Bundled replay dataset.** Replay mode is driven by `engine/testdata/chain-*.json`, a canned phishing-to-DC timeline that runs through the real pipeline with no Splunk instance. This is what `./unravel --mode=replay` plays.

**Example live configuration.** A representative live-mode invocation, with HEC write-back enabled:

```bash
./unravel \
  --mode=live \
  --splunk-url=https://splunk:8089 \
  --splunk-token=<token> \
  --splunk-search="search index=sysmon" \
  --gemini-key=$GEMINI_API_KEY \
  --hec-url=https://splunk:8088 \
  --hec-token=<hec-token> \
  --hec-index=causal_engine \
  --insecure
```

## 5. Architecture and How AI Is Used

![Architecture](architecture.svg)

The top-level diagram shows how Unravel reads from and writes back to Splunk, where the AI sits, and the data flow across components. The deep-dive below zooms into the AI seam.

![AI agent architecture](ai-architecture.svg)

### The seven-subcomponent pipeline

Events move left to right through seven stages. Six are pure Go and never call a model; only the seventh narrator does.

| # | Stage | What it does | LLM? |
|---|-------|--------------|------|
| 1 | **Ingest** | Tails Splunk's `services/search/jobs/export` over a long-lived REST stream, with backoff reconnect | No |
| 2 | **Schema mapper** | Per-source parsers turn raw events into typed Go structs (Sysmon EID 1/3/10/11, Windows Security 4624/4625/4672/4768/4769, AD audit) | No |
| 3 | **Graph builder** | Finds-or-creates `Process` / `Host` / `User` nodes and appends typed edges (`spawned`, `authenticated_as`, `accessed_credential`), each carrying timestamp, confidence, and source event ID | No |
| 4 | **Temporal index** | Buckets edges by minute so windowed "which edges touched node X" queries answer in `O(log n + k)` | No |
| 5 | **Suspicion scorer** | Frequency-rarity x temporal decay x structural lift; updates incrementally and assigns stable incident IDs to connected components | No |
| 6 | **Chain extractor** | On threshold crossing, walks backward from the hottest node along highest-scored edges to recover the most suspicious path, then reverses it into chronological order | No |
| 7 | **AI narrator** | Turns the extracted chain into a short narrative, missing-evidence hypotheses, and ranked containment actions | **Yes** |

The graph lives in a custom in-memory adjacency structure and snapshots to BadgerDB on a timer. Everything ships as one static Go binary with the React UI compiled inside it.

Unravel talks to Splunk three ways: **live ingest** tails the REST export endpoint; **HEC write-back** posts the reconstructed chain back as notable events when `--hec-url` is set; and in live mode with `--splunk-mcp-url`, the narrator's evidence-gathering routes through the official Splunk MCP Server.

### How AI is used

Two agents sit at the seam, both on **Gemini 3.1 Flash Lite** (Google). The static system-instruction prefix benefits from Gemini's implicit context caching. The LLM only ever enriches its own input; the Go engine has already settled what the attack chain is before the narrator runs.

- **Narrator.** Receives the extracted chain as structured JSON and can run up to three rounds of tool calls before narrating, each building and running a real SPL query through a Splunk searcher: `lookup_process_reputation`, `get_account_logon_history`, `fetch_raw_events`, and `splunk_search` (a free-form read-only SPL escape hatch).
- **Threat-intel agent.** Enriches the chain's techniques against live external sources via tool calls: `lookup_technique_intel` (MITRE ATT&CK), `lookup_kev` (CISA Known Exploited Vulnerabilities), and `search_cve` (NVD).
- **Tool-use enrichment loop and read-only SPL guard.** Every SPL query the narrator builds is read-only; the guard enforces that no tool can mutate Splunk state.
- **Splunk MCP / SAIA routing.** With `--splunk-mcp-url` set, enrichment SPL runs via the server's `splunk_run_query` tool over the MCP streamable-HTTP transport instead of direct REST. The narrator also picks up `splunk_nl_search`: it hands a natural-language question to the Splunk AI Assistant (`saia_generate_spl`) for SPL, then runs that SPL through `splunk_run_query`. Tool names are resolved from the server's `tools/list` on connect, degrading gracefully if renamed or unlicensed.
- **Deterministic fallbacks.** With no API key, the narrator falls back to a deterministic stub and the intel agent to a bundled ATT&CK snapshot, so every UI tab works with zero keys.

## Tech Stack

| Layer | Choice |
|-------|--------|
| Engine | Go 1.25 (single static binary) |
| Graph store | Custom in-memory adjacency + BadgerDB snapshots |
| Splunk read | REST `search/jobs/export` tail |
| Splunk write-back | HEC notable events |
| Transport | `gorilla/websocket` |
| UI | React 18 + Vite + TypeScript |
| Graph view | Cytoscape.js + Cola layout |
| Models | Gemini 3.1 Flash Lite (Google) |
| Threat intel | CISA KEV + NVD, with a bundled offline snapshot |

## Repository Layout

```
.
├── README.md                         this file
├── architecture.svg                  architecture diagram
├── ai-architecture.svg               AI agent deep-dive diagram
├── causal-reconstruction-engine.md   detailed design doc
├── LICENSE                           MIT
├── spec/                             implementation specs
│
├── engine/                           Go module (github.com/luigifernandez/unravel)
│   ├── cmd/engine/                   binary entry point, flags, mode dispatch
│   └── internal/
│       ├── types/                    events, nodes, edges, WebSocket envelope
│       ├── schema/                   per-source event parsers (sysmon, winsec, adaudit)
│       ├── graph/                    in-memory adjacency, temporal index, BadgerDB persist
│       ├── scorer/                   incremental suspicion scoring
│       ├── chain/                    backward-walk chain extractor
│       ├── mitre/                    deterministic ATT&CK technique mapping
│       ├── splunk/                   REST source + searcher, mock source, HEC client
│       ├── ai/                       Gemini narrator + threat-intel agent, tool-use, stubs
│       ├── intel/                    live KEV/NVD sources + mock fixtures
│       ├── api/                      HTTP + WebSocket server, broadcaster, embedded UI
│       ├── pipeline/                 wires it all into the streaming loop
│       └── setup/                    first-run setup wizard: config file, prompts, browser open
│
└── ui/                               React + Vite + TypeScript front end
    └── src/                          graph view, panels, time scrubber, incident map, ws client
```

## Team

Built by **Luigi Fernandez** and **Sean Pashaev**.

## License

MIT. See [LICENSE](LICENSE).
