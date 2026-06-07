# Bug: discoverTimelines picks up UI fixture as a replay timeline

Owner: luigi
Scope: `engine/cmd/engine/main.go`
Status: fixed (2026-06-06)
Surfaced: 2026-06-06, during L1 smoke testing (PR #1)

---

## Symptom

Running the canonical replay command from the repo root fails:

```
cd engine
go run ./cmd/engine --mode=replay --testdata=testdata
```

emits:

```
entry 5 (): no parseable timestamp
```

and the mock source produces zero events, so the UI never sees a `graph_update` or `chain_result`.

This is the command the README and CLAUDE.md tell judges to run. The bug breaks the headline replay flow end to end. The L1 smoke test worked around it with a temp `testdata` dir containing only the events file.

## Root cause

`discoverTimelines` in `engine/cmd/engine/main.go` (the helper around line 201) matches every file in `--testdata` whose name starts with `chain-` and ends with `.json`. Two files in `engine/testdata/` match:

- `chain-phishing-events.json` - the real engine timeline. Array of `{ "source": "...", "event": { ... } }` records that `MockSource.NewMockFromFiles` knows how to read.
- `chain-phishing.json` - a UI fixture in the WebSocket envelope shape (`{ "type": "graph_update", "payload": { ... } }`). Used by the standalone mock WS server under `ui/mock-server/`. The mock source has no idea how to parse it; it falls through to "no parseable timestamp" and silently produces zero events.

Both files share the `chain-` prefix that the glob assumes is unique to engine timelines, so the mock source loads both and the UI fixture poisons the run.

## Fix

Pick the smallest change that makes the canonical command work. In rough order of preference:

1. Tighten the discovery filter in `discoverTimelines` to only match engine timelines, e.g. `strings.HasSuffix(e.Name(), "-events.json")` instead of (or in addition to) the `chain-` prefix check. Cheapest, no file moves, no docs to update.
2. Move `engine/testdata/chain-phishing.json` out of the engine's testdata tree. It is consumed by `ui/mock-server/`, not by the engine. A path like `ui/mock-server/fixtures/chain-phishing.json` already exists per CLAUDE.md, so check whether the engine copy is stale and just delete it, or alias it to the UI copy.
3. Both. Tighten the filter so a future stray non-events JSON in `testdata/` can't reintroduce the same bug, AND move the misfiled fixture so the testdata directory only contains engine inputs.

The L1 subagent recommended option 1; option 3 is the durable fix.

## Verification

Before touching anything:

```
cd engine
go run ./cmd/engine --mode=replay --testdata=testdata 2>&1 | head -20
```

should reproduce the `no parseable timestamp` failure. If it does not, the bug has already been fixed or the fixture set has changed - stop and investigate before making changes.

After the fix:

- [ ] `go run ./cmd/engine --mode=replay --testdata=testdata` runs without the timestamp error and emits events (you should see narration arrive in the WebSocket within a few seconds).
- [ ] `go test ./...` from `engine/` is still green. Pay attention to `e2e_test.go` since it exercises the same path with a different testdata dir; it must not regress.
- [ ] If you went with option 2 or 3, grep the repo for any other consumer of `engine/testdata/chain-phishing.json` (`rg -n 'chain-phishing\.json'` from the repo root) and update or remove them. `ui/mock-server/fixtures/chain-phishing.json` should be the only remaining copy.
- [ ] If you went with option 1, add a one-line unit test next to `discoverTimelines` that drops both file shapes into a `t.TempDir()` and asserts only the events file is returned. Cheap insurance.

## Out of scope

- Refactoring `MockSource` to skip files it cannot parse instead of erroring. The error is the right signal; the fix is at the discovery layer, not at the parser.
- Renaming the events fixture. Its current name is referenced from the spec and is the canonical kill-chain timeline.

## Resolution (2026-06-06)

Went with option 3 (durable fix). Changes:

- `engine/cmd/engine/main.go` - `discoverTimelines` now requires the `-events.json` suffix instead of just the `chain-` prefix. Engine replay timelines are the only files in the testdata root that carry that suffix, so non-engine JSON cannot be picked up even if it shares the `chain-` prefix.
- `engine/testdata/chain-phishing.json` -> `engine/internal/types/testdata/chain-phishing.json`. The WS-envelope fixture moved next to its only engine consumer (`internal/types/ws_test.go`). `ui/mock-server/fixtures/chain-phishing.json` is unchanged and remains the canonical UI copy. The engine and UI copies are byte-identical today; the engine copy is kept private to the `types` package rather than removed to avoid an ugly cross-tree relative path from `ws_test.go` into `ui/`.
- `engine/internal/types/ws_test.go` - fixture path updated to the new local `testdata/` location.
- `engine/cmd/engine/main_test.go` (new) - `TestDiscoverTimelines_OnlyMatchesEventsFiles` drops both file shapes (`chain-phishing-events.json` and `chain-phishing.json`) into a `t.TempDir()` and asserts only the events file is returned. Cheap insurance against the same bug class reappearing.

Verification performed:

- `go run ./cmd/engine --mode=replay --testdata=testdata` boots without the `no parseable timestamp` error.
- `go test ./...` from `engine/` green, including the e2e smoke test and the rewired `internal/types` fixture test.

Doc references left alone: `spec/luigi-engine.md` lines 223 and 290 still say `testdata/chain-phishing.json`, but that's the original Phase 1 planning doc and its naming predates the `-events.json` convention. The engine has used `chain-phishing-events.json` since L1 landed. Not touching historical planning artifacts.

Convention going forward: engine replay timelines under `engine/testdata/` MUST end in `-events.json`. Other JSON shapes (WS envelopes, UI fixtures, etc.) must live elsewhere or use a different suffix.
