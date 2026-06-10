import { describe, it, expect } from 'vitest'
import { eventTimestamps, stepTs, tsToPercent, maxConfidenceAt } from '../timeline'
import type { WsEdge } from '../ws'

const edge = (id: string, ts: number, confidence = 0.5): WsEdge => ({
  id, src: 'a', dst: 'b', kind: 'spawned', ts, confidence,
})

describe('eventTimestamps', () => {
  it('returns an empty array for no edges', () => {
    expect(eventTimestamps([])).toEqual([])
  })

  it('de-duplicates timestamps shared by multiple edges', () => {
    const ts = eventTimestamps([edge('e1', 100), edge('e2', 100), edge('e3', 200)])
    expect(ts).toEqual([100, 200])
  })

  it('sorts ascending regardless of input order', () => {
    const ts = eventTimestamps([edge('e1', 300), edge('e2', 100), edge('e3', 200)])
    expect(ts).toEqual([100, 200, 300])
  })
})

describe('stepTs', () => {
  const ts = [100, 200, 300]

  it('returns current when the list is empty', () => {
    expect(stepTs([], 150, 'next')).toBe(150)
    expect(stepTs([], 150, 'prev')).toBe(150)
  })

  it('steps to the next timestamp after current', () => {
    expect(stepTs(ts, 100, 'next')).toBe(200)
    expect(stepTs(ts, 150, 'next')).toBe(200)
  })

  it('steps to the previous timestamp before current', () => {
    expect(stepTs(ts, 300, 'prev')).toBe(200)
    expect(stepTs(ts, 250, 'prev')).toBe(200)
  })

  it('clamps next at the last timestamp', () => {
    expect(stepTs(ts, 300, 'next')).toBe(300)
    expect(stepTs(ts, 999, 'next')).toBe(300)
  })

  it('clamps prev at the first timestamp', () => {
    expect(stepTs(ts, 100, 'prev')).toBe(100)
    expect(stepTs(ts, 0, 'prev')).toBe(100)
  })
})

describe('tsToPercent', () => {
  it('maps the endpoints to 0 and 100', () => {
    expect(tsToPercent(100, 100, 300)).toBe(0)
    expect(tsToPercent(300, 100, 300)).toBe(100)
  })

  it('maps the midpoint to 50', () => {
    expect(tsToPercent(200, 100, 300)).toBe(50)
  })

  it('returns 100 for a degenerate range', () => {
    expect(tsToPercent(100, 100, 100)).toBe(100)
  })
})

describe('maxConfidenceAt', () => {
  it('returns the highest confidence among edges sharing a ts', () => {
    const edges = [edge('e1', 100, 0.3), edge('e2', 100, 0.8), edge('e3', 200, 0.9)]
    expect(maxConfidenceAt(edges, 100)).toBe(0.8)
  })

  it('returns 0 when no edge matches the ts', () => {
    expect(maxConfidenceAt([edge('e1', 100, 0.5)], 999)).toBe(0)
  })
})
