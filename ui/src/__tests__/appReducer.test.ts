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

  it('set_tab changes the active tab', () => {
    const s = reducer(initialState, { type: 'set_tab', payload: 'attack' })
    expect(s.activeTab).toBe('attack')
  })

  it('chain_result creates an incident keyed by incident_id and auto-activates it', () => {
    const s = reducer(initialState, {
      type: 'chain_result',
      payload: {
        incident_id: 'inc-0',
        incident_label: 'WS01',
        confidence: 0.9,
        steps: [{ event_id: 'e1', description: 'd', confidence: 0.9, ts: 100 }],
      },
    })
    expect(s.activeIncidentId).toBe('inc-0')
    expect(s.incidents['inc-0'].label).toBe('WS01')
    expect(s.incidents['inc-0'].awaitingIntel).toBe(true)
    expect(s.incidents['inc-0'].firstSeen).toBe(100)
  })

  it('routes two incidents into separate buckets without clobbering', () => {
    let s = reducer(initialState, {
      type: 'chain_result',
      payload: { incident_id: 'inc-0', incident_label: 'WS01', confidence: 0.9, steps: [{ event_id: 'e1', description: 'd', confidence: 0.9, ts: 100 }] },
    })
    s = reducer(s, {
      type: 'chain_result',
      payload: { incident_id: 'inc-1', incident_label: 'WS02', confidence: 0.8, steps: [{ event_id: 'e2', description: 'd', confidence: 0.8, ts: 200 }] },
    })
    expect(Object.keys(s.incidents)).toHaveLength(2)
    expect(s.incidents['inc-0'].label).toBe('WS01')
    expect(s.incidents['inc-1'].label).toBe('WS02')
  })

  it('a new incident auto-activates but updating an existing one keeps the selection', () => {
    let s = reducer(initialState, {
      type: 'chain_result',
      payload: { incident_id: 'inc-0', incident_label: 'WS01', confidence: 0.9, steps: [{ event_id: 'e1', description: 'd', confidence: 0.9, ts: 100 }] },
    })
    s = reducer(s, {
      type: 'chain_result',
      payload: { incident_id: 'inc-1', incident_label: 'WS02', confidence: 0.8, steps: [{ event_id: 'e2', description: 'd', confidence: 0.8, ts: 200 }] },
    })
    expect(s.activeIncidentId).toBe('inc-1')
    s = reducer(s, {
      type: 'chain_result',
      payload: { incident_id: 'inc-0', incident_label: 'WS01', confidence: 0.95, steps: [{ event_id: 'e1', description: 'd', confidence: 0.95, ts: 100 }, { event_id: 'e3', description: 'd', confidence: 0.9, ts: 150 }] },
    })
    expect(s.activeIncidentId).toBe('inc-1')
    expect(s.incidents['inc-0'].chain?.steps).toHaveLength(2)
    expect(s.incidents['inc-0'].firstSeen).toBe(100)
  })

  it('select_incident changes the active incident', () => {
    let s = reducer(initialState, {
      type: 'chain_result',
      payload: { incident_id: 'inc-0', incident_label: 'WS01', confidence: 0.9, steps: [] },
    })
    s = reducer(s, { type: 'select_incident', payload: 'inc-0' })
    expect(s.activeIncidentId).toBe('inc-0')
  })

  it('narration and threat_intel route to the matching incident', () => {
    let s = reducer(initialState, {
      type: 'chain_result',
      payload: { incident_id: 'inc-0', incident_label: 'WS01', confidence: 0.9, steps: [] },
    })
    s = reducer(s, { type: 'narration', payload: { incident_id: 'inc-0', text: 'story', hypotheses: [], actions: [] } })
    s = reducer(s, { type: 'threat_intel', payload: { incident_id: 'inc-0', status: 'ok', summary: 'x', techniques: [], cve_matches: [] } })
    expect(s.incidents['inc-0'].narration?.text).toBe('story')
    expect(s.incidents['inc-0'].awaitingNarration).toBe(false)
    expect(s.incidents['inc-0'].threatIntel?.summary).toBe('x')
    expect(s.incidents['inc-0'].awaitingIntel).toBe(false)
  })

  it('a narration arriving before its chain creates a placeholder incident', () => {
    const s = reducer(initialState, { type: 'narration', payload: { incident_id: 'inc-7', text: 'early', hypotheses: [], actions: [] } })
    expect(s.incidents['inc-7'].narration?.text).toBe('early')
    expect(s.incidents['inc-7'].chain).toBeNull()
  })

  it('overlay messages without an incident_id fall into inc-legacy', () => {
    const s = reducer(initialState, { type: 'chain_result', payload: { confidence: 0.9, steps: [] } })
    expect(s.incidents['inc-legacy']).toBeDefined()
    expect(s.activeIncidentId).toBe('inc-legacy')
  })

  it('agent_activity appends to the matching incident activity feed in order', () => {
    let s = reducer(initialState, {
      type: 'chain_result',
      payload: { incident_id: 'inc-0', incident_label: 'WS01', confidence: 0.9, steps: [] },
    })
    s = reducer(s, { type: 'agent_activity', payload: { incident_id: 'inc-0', agent: 'narrator', seq: 0, kind: 'tool_call', tool: 'lookup_process_reputation', source: 'Splunk threat_intel index', label: 'Checking lsass.exe' } })
    s = reducer(s, { type: 'agent_activity', payload: { incident_id: 'inc-0', agent: 'narrator', seq: 1, kind: 'tool_result', tool: 'lookup_process_reputation', source: 'Splunk threat_intel index', label: 'Checking lsass.exe', detail: 'flagged malicious', status: 'ok' } })
    expect(s.incidents['inc-0'].activity).toHaveLength(2)
    expect(s.incidents['inc-0'].activity[1].detail).toBe('flagged malicious')
  })

  it('a new incident opens the Investigation tab to show the agents working', () => {
    const s = reducer(initialState, {
      type: 'chain_result',
      payload: { incident_id: 'inc-0', incident_label: 'WS01', confidence: 0.9, steps: [] },
    })
    expect(s.activeTab).toBe('trace')
  })

  it('a fresh chain_result resets the activity feed (a new run starts a new feed)', () => {
    let s = reducer(initialState, {
      type: 'chain_result',
      payload: { incident_id: 'inc-0', incident_label: 'WS01', confidence: 0.9, steps: [] },
    })
    s = reducer(s, { type: 'agent_activity', payload: { incident_id: 'inc-0', agent: 'narrator', seq: 0, kind: 'done', label: 'done' } })
    expect(s.incidents['inc-0'].activity).toHaveLength(1)
    s = reducer(s, {
      type: 'chain_result',
      payload: { incident_id: 'inc-0', incident_label: 'WS01', confidence: 0.95, steps: [{ event_id: 'e1', description: 'd', confidence: 0.9, ts: 1 }] },
    })
    expect(s.incidents['inc-0'].activity).toHaveLength(0)
  })

  it('agent_activity arriving before its chain creates a placeholder incident', () => {
    const s = reducer(initialState, { type: 'agent_activity', payload: { incident_id: 'inc-9', agent: 'intel', seq: 0, kind: 'tool_call', tool: 'lookup_kev', source: 'CISA KEV', label: 'Searching CISA KEV' } })
    expect(s.incidents['inc-9'].activity).toHaveLength(1)
    expect(s.incidents['inc-9'].chain).toBeNull()
  })
})
