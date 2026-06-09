# Causal Reconstruction Engine

A SOC analyst responding to a PowerShell alert in Splunk faces 30+ minutes of
manual pivoting to answer one question: what spawned this process, did it touch
credentials, and did that credential move laterally to the Domain Controller?
This engine answers that question continuously and automatically. It tails a
Splunk deployment in real time, builds a typed provenance graph from endpoint
and identity telemetry, scores edges against a learned baseline, and extracts
the maximally suspicious causal chain the moment a connected subgraph crosses a
threshold.

Built for the Splunk Agentic Ops Hackathon (Security track). The thesis is
engine first, AI second: six of the seven subcomponents are pure Go with zero
LLM calls. A single structured LLM call at the end narrates the extracted chain
in plain English. Run the engine in AI-off mode and it still reconstructs the
attack chain - the LLM is the last hop, not the core.

## Architecture

![Architecture](architecture.svg)

The engine pipeline: ingest layer, schema mapper, provenance graph builder,
temporal causal index, suspicion scorer, chain extractor, and AI narrator. Only
the narrator touches an LLM. All other components are pure Go.

## Quickstart: Replay mode

No Splunk instance or lab required. Prerequisites: Go 1.25+ and Node 20+.

```bash
cd engine
make release          # builds the React UI then compiles the Go binary
./engine --mode=replay
```

Open `http://localhost:8080/`. The engine feeds a canned 5-step kill chain
(phishing to Domain Controller compromise) through the full pipeline and streams
the resulting graph and narration to the browser.

## Quickstart: Live mode

```bash
cd engine
./engine \
  --mode=live \
  --splunk-url=https://<splunk>:8089 \
  --splunk-token=<token> \
  --anthropic-key=$ANTHROPIC_API_KEY \
  --insecure
```

Add `--insecure` for self-signed certs (GOAD and most lab Splunk installs). Omit it for a Splunk instance with a valid CA-signed certificate.

See `spec/sean-ui-lab.md` for lab bring-up instructions (GOAD-lite 3-VM
topology, Splunk Universal Forwarder configuration, and the Python attack
runner).

## Repository layout

| Path | Contents |
|------|----------|
| `engine/` | Go engine binary - all 7 subcomponents, WebSocket server, operating modes |
| `ui/` | React 18 + Cytoscape.js front end, embedded in the engine binary |
| `lab/` | GOAD topology (Vagrant + Ansible), Splunk forwarder config, attack runner |
| `spec/` | Per-owner task specs for engine (Luigi) and UI/lab (Sean) |

## License

MIT - see [LICENSE](LICENSE)
