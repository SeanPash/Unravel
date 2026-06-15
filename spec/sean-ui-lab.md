# UI and Lab Spec - Sean

Owner: sean
Scope: React UI, WebSocket client, GOAD lab topology, Splunk forwarder config, Python attack runner

---

## Repository Layout

```
ui/
├── src/
│   ├── App.tsx                 top-level layout, WebSocket lifecycle
│   ├── ws.ts                   WebSocket client, message dispatch
│   ├── GraphView.tsx           Cytoscape.js graph canvas
│   ├── NarrationPanel.tsx      narration text, hypotheses, containment actions
│   └── TimeScrubber.tsx        time-window filter (replay mode only)
├── mock-server/
│   └── server.ts               Node mock server replaying canned WS messages
├── public/
└── vite.config.ts

lab/
├── topology/                   Vagrant + Ansible for 3-VM GOAD setup
│   ├── Vagrantfile
│   └── ansible/
├── splunk/
│   ├── inputs.conf             Universal Forwarder: Sysmon + Windows Security channels
│   └── outputs.conf            points forwarder at local Splunk instance
└── attack-runner/
    ├── run.py                  sequential Atomic Red Team invocations
    └── atomics.yaml            kill chain step definitions
```

---

## UI Components

### `App.tsx`

Top-level layout. Owns the WebSocket connection lifecycle - connects on mount, reconnects on drop, tears down on unmount.

- Renders two-panel layout: main graph canvas (left/center) + narration sidebar (right)
- Holds top-level state: `nodes`, `edges`, `chain`, `narration`
- Dispatches state updates based on incoming WebSocket message type
- Shows a connection status indicator (connecting / live / reconnecting)

### `ws.ts`

WebSocket client module. Not a React hook - a plain class so it can be unit tested without a DOM.

```ts
class EngineSocket {
  constructor(url: string, handlers: MessageHandlers)
  connect(): void
  close(): void
}

interface MessageHandlers {
  onGraphUpdate(payload: GraphUpdatePayload): void
  onScoreUpdate(payload: ScoreUpdatePayload): void
  onChainResult(payload: ChainResultPayload): void
  onNarration(payload: NarrationPayload): void
}
```

Reconnects with exponential backoff (max 30s). Deserializes messages by `type` field and calls the matching handler. Unknown message types are logged and ignored.

### `GraphView.tsx`

Cytoscape.js wrapper component. Consumes `nodes` and `edges` arrays from props.

- Animates node and edge additions (fade-in over 300ms)
- Colors edges by suspicion score: low score = gray, high score = orange to red gradient
- Highlights the active chain (from the latest `chain_result`) in bright red with increased edge weight
- Node shape by kind: circle (Process), rectangle (Host), diamond (User), triangle (NetFlow)
- Click on a node: shows a tooltip with raw attributes
- The time scrubber filters visible edges to those with `ts` within the selected window

### `NarrationPanel.tsx`

Displays the output of the AI narrator. Updates whenever a `narration` message arrives.

- Narration text in a scrollable prose block
- "Missing evidence" hypotheses as a bulleted list
- Containment actions as a numbered checklist (visual only - no interactivity in MVP)
- Shows a spinner while waiting for the first narration after a chain fires

### `TimeScrubber.tsx`

Replay mode only. A range slider controlling the visible time window in the graph.

- Range: min timestamp to max timestamp seen in received events
- Moving the slider filters `GraphView` to show only edges with `ts` within the window
- "Live" button snaps the scrubber back to the current time (full graph visible)

---

## Mock Server

`ui/mock-server/server.ts` is a small Node WebSocket server that replays a canned message sequence from `ui/mock-server/fixtures/chain-phishing.json`. Sean uses this to build and test the full UI before the Go engine is ready.

Start with: `npx ts-node mock-server/server.ts`

The fixture file mirrors the same `chain-phishing.json` testdata format Luigi uses, so integration is a URL swap (`ws://localhost:8080/ws` instead of the mock).

---

## WebSocket Message Schema

Sean consumes. Luigi produces. This schema is the integration contract - do not change it without coordinating with Luigi.

All messages share the envelope:

```json
{ "type": "<message_type>", "payload": { ... } }
```

### `graph_update`

Incremental. Contains only new or changed nodes and edges since the last update.

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

Node `kind` values: `Process`, `Host`, `User`, `NetFlow`
Edge `kind` values: `spawned`, `connected_to`, `authenticated_as`, `accessed_credential`, `dumped_memory_of`, `read_file`

### `score_update`

Score revision on a previously received edge. Update the edge's color in the graph.

```json
{
  "type": "score_update",
  "payload": { "edge_id": "edge-abc", "score": 0.87 }
}
```

### `chain_result`

A causal chain has been extracted. Highlight these steps in the graph.

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

AI narrator output. Populate the narration panel.

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

## GOAD Lab

Slimmed to 3 VMs for demo-machine performance (full GOAD is 5 VMs; the two extra member servers are dropped).

| VM | Role | OS |
|---|---|---|
| `dc01` | Domain Controller | Windows Server 2019 |
| `ws01` | Workstation (victim) | Windows 10 |
| `kali` | Attacker | Kali Linux |

All VMs managed by Vagrant with an Ansible provisioner. Config lives in `lab/topology/`.

`dc01` and `ws01` run Splunk Universal Forwarder pointed at a local Splunk Enterprise instance (can run on the demo host or in a 4th VM).

### Splunk Forwarder Config

`lab/splunk/inputs.conf` monitors:

- Sysmon operational log: `WinEventLog://Microsoft-Windows-Sysmon/Operational` (EID 1, 3, 10, 11)
- Windows Security log: `WinEventLog://Security` (EID 4624, 4625, 4672, 4768, 4769)
- AD audit events: `WinEventLog://Directory Service`

`lab/splunk/outputs.conf` points at the local Splunk HEC endpoint.

---

## Attack Runner

`lab/attack-runner/run.py` invokes Atomic Red Team atomics in the fixed kill chain order with configurable delays between steps. Deterministic so the demo is reproducible.

### Kill Chain Steps

| Step | Atomic | Description |
|---|---|---|
| 1 | T1566.001 | Phishing: deliver macro-enabled document to `ws01` |
| 2 | T1059.001 | Macro spawns PowerShell on `ws01` |
| 3 | T1003.001 | PowerShell dumps LSASS credentials |
| 4 | T1550.003 | Pass-the-ticket: authenticate to `dc01` with dumped Kerberos ticket |
| 5 | T1078.002 | Domain admin logon to `dc01` |

### Usage

```bash
python run.py --speed normal    # 30s between steps (default)
python run.py --speed fast      # 5s between steps (rehearsal)
python run.py --speed instant   # no delay (CI / smoke test)
python run.py --step 3          # run a single step (debugging)
```

---

## Test Strategy

- `vitest` unit tests in `ui/src/__tests__/`
- `ws.test.ts`: message dispatch on all four message types using canned JSON fixtures, unknown type ignored, reconnect logic tested with a fake WebSocket
- `GraphView.test.tsx`: node/edge state transitions on `graph_update`, score color update on `score_update`, chain highlight on `chain_result`
- Manual browser smoke test: `npm run dev` against the mock server, run the full fixture sequence, verify graph animates and narration panel populates

Run with: `vitest` from `ui/`

---

## Full MVP Task Checklist

### Project setup

- [ ] Initialize Vite + React 18 + TypeScript project in `ui/`
- [ ] Install Cytoscape.js and React wrapper
- [ ] Configure vitest

### WebSocket client

- [ ] `ws.ts`: `EngineSocket` class with connect/close/reconnect
- [ ] `ws.ts`: message deserialization and handler dispatch
- [ ] Unit tests: all four message types, unknown type, reconnect

### App shell

- [ ] `App.tsx`: two-panel layout (graph canvas + narration sidebar)
- [ ] `App.tsx`: WebSocket lifecycle (connect on mount, reconnect on drop)
- [ ] `App.tsx`: top-level state and dispatch to child components

### Graph view

- [ ] `GraphView.tsx`: Cytoscape.js mount and teardown
- [ ] `GraphView.tsx`: incremental node/edge add with fade-in animation
- [ ] `GraphView.tsx`: edge color by suspicion score (gray to red gradient)
- [ ] `GraphView.tsx`: chain highlight on `chain_result`
- [ ] `GraphView.tsx`: node shape by kind
- [ ] `GraphView.tsx`: click tooltip with raw node attributes
- [ ] Unit tests: state transitions on graph_update and score_update

### Narration panel

- [ ] `NarrationPanel.tsx`: narration prose, hypotheses list, actions checklist
- [ ] `NarrationPanel.tsx`: spinner while awaiting first narration after chain fires

### Time scrubber

- [ ] `TimeScrubber.tsx`: range slider bound to event timestamp range
- [ ] `TimeScrubber.tsx`: filter passed to `GraphView` as a time window prop
- [ ] `TimeScrubber.tsx`: "Live" button snaps back to full graph

### Mock server

- [ ] `mock-server/server.ts`: WebSocket server replaying fixture sequence
- [ ] `mock-server/fixtures/chain-phishing.json`: 5-step kill chain WS message sequence

### Lab topology

- [ ] `lab/topology/Vagrantfile`: 3-VM definition (dc01, ws01, kali)
- [ ] `lab/topology/ansible/`: provisioning playbooks for AD setup and Splunk forwarder install
- [ ] `lab/splunk/inputs.conf`: Sysmon + Windows Security + AD channels
- [ ] `lab/splunk/outputs.conf`: HEC endpoint config

### Attack runner

- [ ] `lab/attack-runner/atomics.yaml`: kill chain step definitions
- [ ] `lab/attack-runner/run.py`: sequential invocation with `--speed` and `--step` flags
- [ ] Smoke test: `--speed instant` runs all 5 steps without error

---

# CURRENT TASKS (post-MVP) - START HERE

> **For new Claude sessions:** the MVP checklist above is complete in code. The React UI is built and tested; the lab scaffolding (Vagrantfile, Ansible, Splunk forwarder config, attack runner) is written but has never been booted against real VMs. Pick up from this section. These tasks are scoped to Sean (UI docs, lab smoke, demo video) and must be done before the hackathon submission.

Status snapshot (as of 2026-06-06): all UI components from the MVP exist with vitest coverage, the mock WebSocket server replays the canned timeline, and the lab files exist but have not been validated end-to-end. See `CLAUDE.md` sections `UI State` and `Lab State` for the per-file summary. The work below closes the gap between "files exist" and "demo-ready."

## S1. Replace ui/README.md with project docs

**Why:** `ui/README.md` is still the default Vite template and tells judges (and future Claudes) nothing about this project. `CLAUDE.md` already calls this out as misleading.

**Where:** `ui/README.md`.

- [ ] Replace the entire file. Sections: what the UI is (Causal Reconstruction Engine front-end), prerequisites (Node version), commands (`npm install`, `npm run dev`, `npm test`, `npm run mock`, `npm run build`), the `VITE_WS_URL` environment variable (and the default `ws://${window.location.host}/ws`), and a note that the engine binary (after Luigi's L1) will serve the production build directly so this dev server is for development only.
- [ ] Keep it under 100 lines. No emojis, no em dashes.

## S2. Boot the GOAD-lite lab end-to-end and capture the seed data

**Why:** `lab/topology/Vagrantfile`, `lab/topology/ansible/`, and `lab/splunk/*.conf` have not been booted on real VMs. Until they have, the "live mode" demo path is unproven and we cannot record a credible demo video.

**Where:** `lab/topology/`, `lab/splunk/`, plus any new docs needed under `lab/README.md`.

- [ ] `vagrant up dc01 ws01 kali` from `lab/topology/`. Resolve provisioning failures by editing the Vagrantfile and Ansible playbooks until all three VMs come up clean from a destroyed state.
- [ ] Install Sysmon on `ws01` and confirm events flow into Splunk. Verify the Universal Forwarder picks up the channels listed in `lab/splunk/inputs.conf` and that they land at the index configured in `outputs.conf`.
- [ ] Run `python lab/attack-runner/run.py --speed instant`. Confirm Splunk receives all five kill chain steps. Save a small slice of the raw events (one per EID family) under `lab/fixtures/` for offline debugging.
- [ ] Write `lab/README.md`: prerequisites (Vagrant, VirtualBox, Splunk Enterprise), one-shot bring-up command, attack-runner invocation, teardown command. Reference it from the repo-root `README.md` Luigi will create.

## S3. End-to-end demo run with the engine binary

**Why:** The replay path is the only path proven today. For the hackathon submission and the demo video, we need to show the live path (lab > Splunk > engine RESTSource > UI) at least once.

**Where:** depends on Luigi's L1 (embedded UI in the engine binary) being done first. Coordinate the merge order.

- [ ] After Luigi's L1 lands, build the engine binary (`go build ./cmd/engine` from `engine/`).
- [ ] Boot the lab (`vagrant up` in `lab/topology/`), point the engine binary at the lab Splunk: `./engine --mode=live --splunk-url=... --splunk-token=... --gemini-key=$GEMINI_API_KEY`.
- [ ] In a second terminal, run `python lab/attack-runner/run.py --speed fast`.
- [ ] Open `http://localhost:8080/` in a browser. Confirm the graph populates, the chain highlights when the threshold trips, and the narration panel fills in.
- [ ] If the chain fires but narration looks weak, re-prompt with Luigi before changing the engine.

## S4. Demo video under 3 minutes

**Why:** Explicit hackathon submission requirement (see `causal-reconstruction-engine.md`).

- [ ] Storyboard a 2:30 take. Suggested beats: 15s problem framing (analysts drown in alerts), 30s architecture (point at `architecture.svg`), 90s live demo (kick off the attack runner, narrate the graph filling in, read the AI narration), 15s call to action. Adjust to fit but stay under 3:00.
- [ ] Record from a clean lab boot. Use the engine binary built in S3, not the dev Vite server, so the URL bar shows a single port.
- [ ] No emojis on overlays. No em dashes in subtitles.
- [ ] Upload to the team's chosen host (YouTube unlisted or similar) and add the link to the repo-root `README.md` Luigi creates.

## Definition of done for this task group

- [ ] `ui/README.md` reads as project docs, not the Vite template.
- [ ] `vagrant up` from a clean checkout brings the lab up without manual fixups, and `attack-runner/run.py` drives a full kill chain into Splunk.
- [ ] A fresh teammate can clone the repo, follow `lab/README.md` + the repo-root `README.md`, and reproduce the live demo on their own machine.
- [ ] A demo video link lives in the repo-root `README.md`.
