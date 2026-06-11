import { describe, it, expect } from 'vitest'
import { reducer, initialState } from '../App'
import type { LogEventPayload } from '../ws'

describe('App reducer', () => {
  it('stores log events keyed by event_id', () => {
    const log: LogEventPayload = { event_id: 'evt-001', ts: 100, source: 'sysmon', raw: { host: 'WS01' } }
    const next = reducer(initialState, { type: 'log_event', payload: log })
    expect(next.logs['evt-001']).toEqual(log)
  })

  it('overwrites a re-delivered log event with the same id', () => {
    const a: LogEventPayload = { event_id: 'evt-001', ts: 100, source: 'sysmon', raw: {} }
    const b: LogEventPayload = { event_id: 'evt-001', ts: 100, source: 'sysmon', raw: { host: 'WS01' } }
    let s = reducer(initialState, { type: 'log_event', payload: a })
    s = reducer(s, { type: 'log_event', payload: b })
    expect(Object.keys(s.logs)).toHaveLength(1)
    expect(s.logs['evt-001'].raw).toEqual({ host: 'WS01' })
  })

  it('sets and clears the focused node', () => {
    let s = reducer(initialState, { type: 'focus_node', payload: 'proc-1' })
    expect(s.focusedNodeId).toBe('proc-1')
    s = reducer(s, { type: 'focus_node', payload: null })
    expect(s.focusedNodeId).toBeNull()
  })

  it('chain_result sets awaitingIntel true', () => {
    const s = reducer(initialState, {
      type: 'chain_result',
      payload: { confidence: 0.9, steps: [], tactics: [] },
    })
    expect(s.awaitingIntel).toBe(true)
  })

  it('threat_intel stores the payload and clears awaitingIntel', () => {
    const mid = reducer(initialState, {
      type: 'chain_result',
      payload: { confidence: 0.9, steps: [], tactics: [] },
    })
    const s = reducer(mid, {
      type: 'threat_intel',
      payload: { status: 'ok', summary: 'x', techniques: [], cve_matches: [] },
    })
    expect(s.awaitingIntel).toBe(false)
    expect(s.threatIntel?.summary).toBe('x')
  })

  it('set_tab changes the active tab', () => {
    const s = reducer(initialState, { type: 'set_tab', payload: 'attack' })
    expect(s.activeTab).toBe('attack')
  })
})
