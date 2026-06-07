# Unravel

Unravel is a Causal Reconstruction Engine for Splunk. It tails Sysmon, Windows Security, and Active Directory audit events out of Splunk, builds an in-memory causal graph as the events arrive, scores edges online, extracts the most suspicious chain when scores cross a threshold, and asks Claude Sonnet 4.6 to narrate what happened. The architectural north star is engine first, AI second: six of the seven engine subcomponents contain zero LLM calls, and the AI narrator is the only LLM-touching component. Built for the Splunk Agentic Ops Hackathon, Security track.

## Architecture

![Unravel architecture](architecture.svg)

The pipeline is: Splunk REST tail (or replay MockSource) -> schema mapper -> graph builder + temporal index -> online scorer -> chain extractor -> AI narrator -> WebSocket -> React + Cytoscape UI. The AI narrator is highlighted in the diagram to reinforce that it is the only component that talks to an LLM. Everything upstream is deterministic Go.

## Quickstart: replay demo

The replay path needs no Splunk and no Anthropic key. It runs the canned phishing-to-domain-controller timeline at `engine/testdata/chain-phishing-events.json` against the real pipeline.

In one terminal:

```
cd engine
go test ./...
go run ./cmd/engine --mode=replay --testdata=testdata
```

In another terminal (separate UI process; this goes away once the UI is embedded into the engine binary):

```
cd ui
npm install
npm run dev
```

Open the URL Vite prints. The engine serves the WebSocket on `:8080`; the UI reads `VITE_WS_URL` to find it (defaults to `ws://localhost:8080/ws`). Watch the graph build and the narration appear once the scorer crosses threshold.

## Quickstart: live mode

Live mode needs a Splunk instance reachable over REST and an Anthropic API key.

```
cd engine
export ANTHROPIC_API_KEY=sk-ant-...
go run ./cmd/engine \
  --mode=live \
  --splunk-url=https://splunk.example.com:8089 \
  --splunk-token=YOUR_SPLUNK_BEARER_TOKEN \
  --splunk-search='search index=sysmon OR index=wineventlog'
```

Start the UI the same way as the replay quickstart.

## Quickstart: AI off

Same as replay, but swap the Claude narrator for a deterministic stub. Useful when you want to demo the graph without an Anthropic key.

```
cd engine
go run ./cmd/engine --mode=ai-off --testdata=testdata
```

## Repo layout

- `engine/` - Go engine. Ingest, schema mappers, graph, temporal index, scorer, chain extractor, AI narrator, WebSocket server. `cmd/engine` is the binary entry point.
- `ui/` - React + Cytoscape front end plus a standalone WebSocket mock server under `ui/mock-server/` for UI work without the engine running.
- `lab/` - GOAD-lite Vagrant topology, Ansible playbooks, Splunk Universal Forwarder config, and the Atomic Red Team attack runner.
- `spec/` - per-owner specs for engine and UI work.
- `causal-reconstruction-engine.md` - product framing and architecture for the selected Security track.

## Tests

- Engine: `cd engine && go test ./...` runs the full sweep including the `e2e_test.go` smoke test that runs the mock timeline through the real WebSocket and asserts a chain plus narration arrive.
- UI: `cd ui && npm test` runs the vitest suite (`ws.test.ts`, `GraphView.test.tsx`, `smoke.test.ts`).

## License

MIT. See [LICENSE](LICENSE).
