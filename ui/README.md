# Unravel UI

React front-end for the Causal Reconstruction Engine. Renders the live provenance graph emitted by the Go engine, highlights extracted causal chains, and shows the AI narrator's prose, hypotheses, and containment actions.

This package is the development harness for the UI. In production the Go engine binary serves the built assets directly from a single port; this Vite dev server is only used while iterating on the frontend.

## Prerequisites

- Node.js 20 or newer (matches the `@types/node` major in `package.json`).
- npm 10 or newer.

## Install

```
npm install
```

## Commands

- `npm run dev` - Vite dev server with HMR. Defaults to `http://localhost:5173/`.
- `npm test` - vitest single-run sweep (`ws.test.ts`, `GraphView.test.tsx`, `smoke.test.ts`).
- `npm run test:watch` - vitest in watch mode.
- `npm run mock` - standalone WebSocket mock server at `ws://localhost:8080/ws`. Replays `mock-server/fixtures/chain-phishing.json` for development without the Go engine.
- `npm run build` - production build into `dist/`. The engine binary embeds this directory.
- `npm run lint` - ESLint over the workspace.

## Environment

- `VITE_WS_URL` - WebSocket URL the client connects to. Defaults to `ws://${window.location.host}/ws`, which is correct when the engine binary serves the UI itself. Set this when running `npm run dev` against the mock server or a remote engine:

  ```
  VITE_WS_URL=ws://localhost:8080/ws npm run dev
  ```

## Layout

```
src/
  App.tsx              two-pane layout, WebSocket lifecycle, top-level state
  ws.ts                EngineSocket client with reconnect/backoff
  GraphView.tsx        Cytoscape graph canvas, chain highlight, time-window filter
  NarrationPanel.tsx   narration prose, hypotheses, action checklist
  TimeScrubber.tsx     replay-mode time-window slider with Live snap-back
mock-server/
  server.ts            Node WebSocket server that replays the canned timeline
  fixtures/            canned message sequences (phishing kill chain)
```

The WebSocket message contract is defined in `spec/sean-ui-lab.md` and produced by the engine in `engine/internal/api`. Do not change the envelope without coordinating both ends.

## Development against the mock server

In one terminal:

```
npm run mock
```

In another:

```
VITE_WS_URL=ws://localhost:8080/ws npm run dev
```

Open the dev server URL. The mock will stream the phishing timeline and the graph and narration panel should populate end-to-end.

## Development against the engine

Run the engine in replay mode from `engine/`:

```
go run ./cmd/engine --mode=replay --testdata=testdata
```

The engine listens on `:8080` by default. Either point the Vite dev server at it (`VITE_WS_URL=ws://localhost:8080/ws npm run dev`) or, once the engine embeds the built UI, open `http://localhost:8080/` directly.
