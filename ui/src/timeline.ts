// Pure timeline math for the TimeScrubber. Kept free of React so vitest can
// exercise navigation and tick positioning directly. "Events" are the distinct
// edge timestamps; a node effectively appears at the ts of its first edge.

import type { WsEdge } from './ws'

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
