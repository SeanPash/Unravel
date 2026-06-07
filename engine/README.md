# Unravel engine

Go implementation of the Causal Reconstruction Engine. Tails events out of Splunk (or replays a fixture), builds an in-memory provenance graph, scores edges online, extracts the most suspicious chain when scores cross threshold, and asks Claude Sonnet 4.6 to narrate it. Six of the seven engine subcomponents contain zero LLM calls; the AI narrator is the only LLM-touching component.

## Layout

- `cmd/engine` - binary entry point. Handles flag parsing, mode selection, and graceful shutdown.
- `internal/types` - shared event, node, edge, and WebSocket envelope structs.
- `internal/schema` - parsers for Sysmon EID 1/3/10/11, Windows Security 4624/4625/4672/4768/4769, and AD audit object-change events.
- `internal/graph` - in-memory adjacency, time-bucketed temporal index, BadgerDB snapshot persister.
- `internal/scorer` - frequency-rarity, temporal decay, structural lift, and threshold-trigger signal channel.
- `internal/chain` - weighted backward-walk chain extractor with geometric-mean confidence.
- `internal/splunk` - `Source` interface, `MockSource` (timeline replay), `RESTSource` (long-poll + exponential backoff), `HECClient` (chain_result write-back).
- `internal/ai` - `Narrator` interface, `StubNarrator`, `ClaudeNarrator` (Claude Sonnet 4.6 via the Messages API with prompt caching on the system block).
- `internal/api` - HTTP server, WebSocket upgrade, fan-out broadcaster with drop-slow-client semantics, embedded UI assets.
- `internal/pipeline` - wires source -> schema mapper -> graph -> scorer -> chain extractor -> narrator -> broadcaster, with debounced chain extraction.
- `e2e_test.go` - module-root smoke test that runs the mock timeline through the real WebSocket and asserts a chain_result and narration arrive within the deadline.

## Build and test

```
go build ./...
go vet ./...
go test ./...
```

## Build the UI into the binary

The engine binary embeds the React UI via `go:embed` so a single process serves both the WebSocket and the static assets. Stage the UI build into the embed directory before `go build` or `go run` if you want the bundled UI served at `/`:

```
./build-ui.sh
```

The script runs `npm run build` in `../ui` (Vite is configured to write straight into `internal/api/static/`) and restores the `.gitkeep` sentinel afterwards. The embed directory contents are gitignored.

## Run

Replay the canned phishing-to-domain-controller timeline (no Splunk, no Anthropic key):

```
go run ./cmd/engine --mode=replay --testdata=testdata
```

Replay with the deterministic stub narrator (no Anthropic key needed even if the build was compiled with one):

```
go run ./cmd/engine --mode=ai-off --testdata=testdata
```

Live mode (needs a Splunk instance reachable over REST and `ANTHROPIC_API_KEY`):

```
export ANTHROPIC_API_KEY=sk-ant-...
go run ./cmd/engine \
  --mode=live \
  --splunk-url=https://splunk.example.com:8089 \
  --splunk-token=YOUR_SPLUNK_BEARER_TOKEN \
  --splunk-search='search index=sysmon OR index=wineventlog'
```

## Optional flags

- `--hec-url`, `--hec-token`, `--hec-index`, `--hec-sourcetype` - Splunk HEC write-back for each chain_result. Disabled when `--hec-token` is empty (also reads `SPLUNK_HEC_TOKEN`). Defaults: index `main`, sourcetype `unravel:chain`.
- `--insecure` - skip TLS verification for outbound calls to Splunk (REST and HEC). Useful against self-signed lab instances; do not use in production.

## Testdata convention

Replay timelines under `testdata/` MUST end in `-events.json`. `discoverTimelines` in `cmd/engine/main.go` filters on that suffix, so any other JSON shape dropped at the root (WS envelope fixtures, UI mocks, etc.) will be picked up by the mock source and break the replay command with `no parseable timestamp`. WS-envelope fixtures live under `internal/types/testdata/` (engine-private) and `../ui/mock-server/fixtures/` (UI-side canonical copy).
