# Splunk MCP Server: follow-ups

Owner: luigi
Created: 2026-06-13

## Purpose and baseline

This file lists the follow-up work after the Splunk MCP Server searcher landed on
`main` (fast-forward merge, tip commit `4492343`, 9 commits). It is written to be
executed cold, without the conversation that produced it.

What already shipped on `main` (the baseline these follow-ups build on):

- `splunk.MCPSearcher` (`engine/internal/splunk/mcp_searcher.go`): a third
  `ai.SplunkSearcher` that runs the narrator's SPL through the official Splunk MCP
  Server's `splunk_run_query` tool over the MCP streamable-HTTP transport
  (`github.com/modelcontextprotocol/go-sdk` v1.6.1, bearer auth, `--insecure`
  honored). Lazy single session, mutex-guarded, recovers after a transient failure
  (`dropSession`), checks tool-level `IsError`, normalizes rows to the same shape
  `RESTSearcher` returns.
- An autonomous `splunk_search` narrator tool (`engine/internal/ai/claude.go`):
  Claude composes its own read-only SPL, guarded by `isReadOnlySPL` (whitespace-
  normalized command blocklist). Activity-feed source is honest per backend via
  `ClaudeConfig.SearcherName`, set in `buildNarrator`.
- Opt-in wiring: `--splunk-mcp-url` / `--splunk-mcp-token` (live mode; falls back
  to REST when unset; replay unchanged).

Suggested execution order: FU1 first (fast, unblocks a clean `-race`), then FU3
(diagram, required deliverable), then FU2 (the larger stretch), then FU4 (push).

---

## FU1: Clean up the pre-existing `-race` failure

### Goal
`cd engine && go test -race ./...` passes clean across all packages.

### Current state
`go test ./...` is green, but `go test -race ./...` fails on `internal/pipeline`
(`pipeline.go`) and the root e2e test (`chain.go`) with a data race on
`edge.Confidence` between the ingest goroutine and chain extraction. This predates
the MCP work and is unrelated to it (the MCP branch never touched those files).

The fix already exists as a single self-contained commit on branch `feat/overhaul`:

```
68a4df2  fix(engine): eliminate edge.Confidence data race between ingest and chain extraction
  engine/internal/chain/chain.go
  engine/internal/chain/chain_test.go
  engine/internal/graph/graph.go
  engine/internal/pipeline/pipeline.go
```

`68a4df2` is NOT in `main`. Do NOT merge `feat/overhaul` wholesale: it is 48
commits ahead of `main` and 32 behind, so a merge would pull in large unrelated
work. Cherry-pick the one fix instead.

### Steps
1. From `main`:
   ```bash
   git cherry-pick 68a4df2
   ```
2. If it applies cleanly, skip to step 4. If it conflicts (likely in `chain.go` /
   `pipeline.go`, since `main` and `feat/overhaul` have diverged), resolve by hand
   using the intent of the fix (described below), then `git cherry-pick --continue`.
   If conflicts are messy, abort (`git cherry-pick --abort`) and re-apply the
   change manually per "The fix" below.
3. The fix (so it can be re-applied by hand if needed):
   - Add `graph.SetEdgeConfidence(id, score)` that writes the edge's `Confidence`
     field under the graph lock.
   - In `pipeline.handleRaw`, call `graph.SetEdgeConfidence(...)` instead of
     writing `edge.Confidence` directly.
   - In `pipeline.handleSignal`, make the `scoreFn` passed to chain extraction
     `scorer.EdgeScore` (a mutex-guarded read of the scorer's `edgeScores` map)
     rather than reading `edge.Confidence`.
   - In `chain.Extract`, take each path step's confidence from `score(best.ID)`
     rather than `best.Confidence`.
   - Behavioral note: a chain step's confidence now comes from the passed
     `ScoreFn`, not the edge's stored `Confidence`. These are identical in
     production because the pipeline sets both to the same score.
4. Verify:
   ```bash
   cd engine && go test ./... && go test -race ./...
   ```
   Both must be clean across all packages.

---

## FU2: Stretch - generate SPL via the Splunk AI Assistant (`saia_generate_spl`)

### Goal
Stack a second Splunk-AI capability onto the bonus story: let the narrator ask the
Splunk MCP Server's AI Assistant to turn a natural-language question into SPL, then
run that SPL via `splunk_run_query`. This makes the flow "Claude asks Splunk's own
AI Assistant to write the SPL, then executes it through MCP," strengthening both
"leverage Splunk's AI capabilities" and "Best Use of Splunk MCP Server."

### Recommendation
This crosses the `ai.SplunkSearcher` interface boundary and adds agentic chaining,
so run it through `superpowers:brainstorming` -> `writing-plans` like the main
feature rather than coding straight from this seed. The design intent and the key
decision are below.

### Background
The Splunk MCP Server exposes AI Assistant tools alongside `splunk_run_query`:
`saia_generate_spl` (natural language -> SPL), `saia_explain_spl`,
`saia_optimize_spl`, `saia_ask_splunk_question`. Today `MCPSearcher` only calls
`splunk_run_query`. Confirm the exact `saia_generate_spl` input/output field names
against the live server's `tools/list` before coding (the input is likely a
natural-language `text`/`question` string; the output carries the generated SPL).

### Design intent
- Add a narrator tool, e.g. `splunk_nl_search`, input `{ "question": string }`.
- Its dispatch chains two MCP calls inside one narrator tool:
  1. `saia_generate_spl(question)` -> SPL string.
  2. Guard the SPL with the existing `isReadOnlySPL`.
  3. Run it via the existing `splunk_run_query` path (reuse `MCPSearcher.Search`).
- Surface both sub-steps to the activity feed (so the demo shows "Splunk AI
  Assistant generated SPL" then "ran it via Splunk MCP Server").

### Key decision: the interface boundary
`saia_generate_spl` is MCP-only; `RESTSearcher` and `MockSearcher` cannot do it.
Keep the one-method `ai.SplunkSearcher` untouched and add a SECOND optional
capability interface, for example:

```go
// in internal/ai
type SPLGenerator interface {
    GenerateSPL(ctx context.Context, question string) (string, error)
}
```

Implement `GenerateSPL` on `MCPSearcher` only (calls `saia_generate_spl`). In the
narrator, type-assert the configured `Searcher` to `SPLGenerator`; offer the
`splunk_nl_search` tool only when the assertion succeeds. This makes the tool
appear automatically in live+MCP mode and stay absent for REST/replay, with no
change to `ai.SplunkSearcher`.

### Touch points
- `engine/internal/splunk/mcp_searcher.go`: add `GenerateSPL`, calling
  `saia_generate_spl` and extracting the SPL from the result text (reuse `mcpText`).
- `engine/internal/ai/claude.go`: add the `splunk_nl_search` tool definition, gate
  it on `SPLGenerator`, and a dispatch that chains generate -> guard -> run.
- `engine/internal/ai/activity.go`: activity labels for `splunk_nl_search` (source
  "Splunk AI Assistant" for the generate step).

### Tests
- Unit: `GenerateSPL` result parsing.
- In-memory MCP server test (mirror `mcp_searcher_test.go`) with a fake
  `saia_generate_spl` tool returning canned SPL.
- Narrator test: `splunk_nl_search` is offered only when the searcher implements
  `SPLGenerator`; dispatch chains generate -> guard -> run; a mutating generated
  SPL is refused by `isReadOnlySPL`.

### Caveats
- `saia_*` tools require the Splunk AI Assistant to be enabled/licensed on the
  instance; this is not guaranteed on every Enterprise trial. Confirm availability
  before relying on it in the recorded demo.
- Stays inside the AI seam: ingest, schema, graph, temporal index, scorer, and
  chain extraction remain LLM-free. Do not let this leak upstream.

---

## FU3: Update the architecture diagram

### Goal
`architecture.svg` (repo root, a required hackathon deliverable) must show the new
narrator-to-MCP-Server path and clearly depict the three required things: how the
app interacts with Splunk, how AI/agents are integrated, and the data flow between
services.

### Steps
1. Open `architecture.svg` (repo root) and check whether it already shows the AI
   narrator and a Splunk hop.
2. Add/confirm these elements:
   - The AI narrator (the only LLM hop) calling the Splunk MCP Server via
     `splunk_run_query` (and `saia_generate_spl` if FU2 is done).
   - The engine's existing Splunk paths: REST `/services/search/jobs/export` tail
     for ingest, and HEC write-back for chain results.
   - Data flow: Splunk -> ingest -> graph/scoring/chain (engine, LLM-free) ->
     narrator (AI) -> MCP Server -> Splunk, and chain results -> HEC -> Splunk.
3. Preserve the "engine first, AI second" framing: the six engine subcomponents
   prominent, AI as the last hop only.
4. If the SVG was generated from a source (e.g. a diagram tool / mermaid), edit the
   source and re-export rather than hand-editing the SVG.

---

## FU4: Push `main` to origin

### Goal
Publish the merged work when ready.

### State
Local `main` is ahead of `origin/main` (9 commits from the MCP work, plus whatever
FU1-FU3 add) and has not been pushed.

### Steps
```bash
git push origin main
```
Pushing is outward-facing and durable; confirm pushing `main` directly is intended
(versus opening a PR) before running it.

---

## Note: local-only design docs

The design spec and execution plan for the shipped MCP feature live under
`docs/superpowers/specs/2026-06-13-splunk-mcp-searcher-design.md` and
`docs/superpowers/plans/2026-06-13-splunk-mcp-searcher.md`. That tree is gitignored
(local-only), so those files are not in the repo. This `spec/` file is tracked and
is the canonical place for these follow-ups.
