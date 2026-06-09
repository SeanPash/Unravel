# Causal Reconstruction Engine - UI

React 18 + TypeScript + Cytoscape.js front-end for the Causal Reconstruction Engine. Connects to the engine's WebSocket server and renders the live provenance graph, suspicion scores, and AI narration.

## Prerequisites

Node 20 or later.

## Commands

```bash
# Install dependencies
npm install

# Development server (proxies WebSocket to engine on :8080 by default)
npm run dev

# Run vitest unit tests
npm test

# Start the Node mock WebSocket server (for UI-only development, no engine needed)
npm run mock

# Build for production (output to dist/)
npm run build
```

## WebSocket URL

The UI connects to `ws://${window.location.host}/ws` by default, which works when served from the engine binary (port 8080). To point at a different engine during development, set `VITE_WS_URL`:

```bash
VITE_WS_URL=ws://localhost:9090/ws npm run dev
```

## Development vs production

During development, use `npm run dev` (Vite dev server with HMR). In production, the engine binary serves the built assets directly after Luigi's L1 is complete, so no separate server is needed. Build with `npm run build`, then `make release` from `engine/` copies the output into the embed directory and compiles it into the binary.

## Mock server

`npm run mock` starts `mock-server/server.ts`, a small WebSocket server that replays the canned kill-chain fixture at `mock-server/fixtures/chain-phishing.json`. Use this to develop the UI without a running engine. Switch to the real engine by changing the WebSocket URL; the message format is identical.
