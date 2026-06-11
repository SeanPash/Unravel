// Pure timeline math for the TimeScrubber. Kept free of React so vitest can
// exercise navigation and tick positioning directly. "Events" are the distinct
// edge timestamps; a node effectively appears at the ts of its first edge.

import type { WsEdge, ChainStep } from './ws'

// Distinct edge timestamps (unix seconds), sorted ascending.
export function eventTimestamps(edges: WsEdge[]): number[] {
  return [...new Set(edges.map(e => e.ts))].sort((a, b) => a - b)
}

// Next ('next') or previous ('prev') distinct ts relative to `current`.
// Clamps at the ends: 'next' at/after the last ts returns the last; 'prev'
// at/before the first ts returns the first. Empty list returns `current`.
export function stepTs(timestamps: number[], current: number, dir: 'next' | 'prev'): number {
  if (timestamps.length === 0) return current
  if (dir === 'next') {
    const nxt = timestamps.find(t => t > current)
    return nxt ?? timestamps[timestamps.length - 1]
  }
  const prevs = timestamps.filter(t => t < current)
  return prevs.length > 0 ? prevs[prevs.length - 1] : timestamps[0]
}

// Position of a ts on the track as a 0..100 percentage. A degenerate range
// (min === max) puts the single tick at the end so it lines up with the thumb.
export function tsToPercent(ts: number, min: number, max: number): number {
  if (max <= min) return 100
  return ((ts - min) / (max - min)) * 100
}

// Highest edge confidence among the edges sharing a timestamp, for tick color.
// Returns 0 when no edge matches.
export function maxConfidenceAt(edges: WsEdge[], ts: number): number {
  let m = 0
  for (const e of edges) if (e.ts === ts && e.confidence > m) m = e.confidence
  return m
}

// Categorical palette for attack phases. Deliberately rotates through the
// dashboard's full accent range instead of leaning on green; order is chosen
// so adjacent phases always contrast.
export const PHASE_COLORS = [
  '#4fa7d9', // blue
  '#f0b429', // amber
  '#dc4e41', // red
  '#9d7cd8', // purple
  '#45b8ac', // teal
  '#e0823c', // orange
]

// Display window for the active incident: the chain's event span padded on
// both sides, so one incident's events spread across the full rail width
// even when the global feed spans hours. Without chain steps the full feed
// range is returned.
export function displayRange(steps: ChainStep[], minTs: number, maxTs: number): [number, number] {
  if (steps.length === 0) return [minTs, maxTs]
  let first = steps[0].ts
  let last = steps[0].ts
  for (const s of steps) {
    first = Math.min(first, s.ts)
    last = Math.max(last, s.ts)
  }
  const pad = Math.max((last - first) * 0.15, 30)
  return [Math.max(minTs, first - pad), Math.min(maxTs, last + pad)]
}

// The highest-confidence edge at a timestamp, used to describe the event in
// the timeline detail strip and to pick a graph node to focus.
export function bestEdgeAt(edges: WsEdge[], ts: number): WsEdge | null {
  let best: WsEdge | null = null
  for (const e of edges) {
    if (e.ts === ts && (best === null || e.confidence > best.confidence)) best = e
  }
  return best
}

// A contiguous slice of the timeline owned by one attack tactic. Phases tile
// [minTs, maxTs] with no gaps: boundaries fall midway between the last event
// of one tactic and the first event of the next.
export interface TimelinePhase {
  name: string
  startTs: number
  endTs: number
  // ts of the phase's first chain step, kept for jump-to-phase navigation.
  firstEventTs: number
  // ts of the phase's last chain step.
  lastEventTs: number
}

// Groups chain steps by tactic and lays the groups out as contiguous segments
// across [minTs, maxTs], ordered by each tactic's first event. When no step
// carries its own tactic but the chain declares an ordered tactic list,
// steps are distributed across that list in order (a display heuristic for
// chains that only report tactics at the top level). No tactics at all
// yields an empty list (callers fall back to a single unlabeled segment).
export function buildPhases(
  steps: ChainStep[],
  tacticOrder: string[] | undefined,
  minTs: number,
  maxTs: number,
): TimelinePhase[] {
  let annotated = steps.filter(s => s.tactic)
  if (annotated.length === 0 && tacticOrder && tacticOrder.length > 0 && steps.length > 0) {
    const sorted = [...steps].sort((a, b) => a.ts - b.ts)
    const n = Math.min(tacticOrder.length, sorted.length)
    const per = Math.ceil(sorted.length / n)
    annotated = sorted.map((s, i) => ({
      ...s,
      tactic: tacticOrder[Math.min(Math.floor(i / per), n - 1)],
    }))
  }

  const groups = new Map<string, { first: number; last: number }>()
  for (const s of annotated) {
    if (!s.tactic) continue
    const g = groups.get(s.tactic)
    if (g === undefined) groups.set(s.tactic, { first: s.ts, last: s.ts })
    else {
      g.first = Math.min(g.first, s.ts)
      g.last = Math.max(g.last, s.ts)
    }
  }
  if (groups.size === 0) return []

  // Callers pass the already-zoomed display range, so the outer phases tile
  // all the way to its edges; interior boundaries fall midway between
  // adjacent tactics.
  const names = [...groups.keys()].sort((a, b) => groups.get(a)!.first - groups.get(b)!.first)
  const phases: TimelinePhase[] = []
  for (let i = 0; i < names.length; i++) {
    const cur = groups.get(names[i])!
    const prev = i > 0 ? groups.get(names[i - 1])! : null
    const next = i < names.length - 1 ? groups.get(names[i + 1])! : null
    const start = prev !== null ? (prev.last + cur.first) / 2 : minTs
    const end = next !== null ? (cur.last + next.first) / 2 : maxTs
    phases.push({
      name: names[i],
      startTs: Math.min(start, end),
      endTs: Math.max(start, end),
      firstEventTs: cur.first,
      lastEventTs: cur.last,
    })
  }
  return phases
}

// Index of the phase containing ts, or -1 when ts falls outside every phase
// (including events that belong to a different incident's chain). Walks from
// the right so a ts on a boundary belongs to the later phase.
export function phaseIndexAt(phases: TimelinePhase[], ts: number): number {
  if (phases.length === 0) return -1
  if (ts < phases[0].startTs || ts > phases[phases.length - 1].endTs) return -1
  for (let i = phases.length - 1; i >= 0; i--) {
    if (ts >= phases[i].startTs) return i
  }
  return -1
}

// Color of the phase containing ts, or null outside every phase. Shared by
// the timeline markers and the log rows so the two cannot drift apart.
export function phaseColorAt(phases: TimelinePhase[], ts: number): string | null {
  const i = phaseIndexAt(phases, ts)
  return i >= 0 ? PHASE_COLORS[i % PHASE_COLORS.length] : null
}
