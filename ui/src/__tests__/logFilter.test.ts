import { describe, it, expect } from 'vitest'
import { selectRelatedLogs } from '../logFilter'
import type { ChainResultPayload, LogEventPayload, WsEdge } from '../ws'

const log = (id: string, ts: number): LogEventPayload => ({
  event_id: id, ts, source: 'sysmon', raw: { host: 'WS01' },
})

const edge = (id: string, src: string, dst: string, eventId?: string): WsEdge => ({
  id, src, dst, kind: 'spawned', ts: 1, confidence: 0.5, source_event_id: eventId,
})

// Steps deliberately out of time order to prove the selector sorts.
const chain: ChainResultPayload = {
  confidence: 0.9,
  steps: [
    { event_id: 'evt-2', description: 'step 2', confidence: 0.9, ts: 200 },
    { event_id: 'evt-1', description: 'step 1', confidence: 0.9, ts: 100 },
  ],
}

const logs: Record<string, LogEventPayload> = {
  'evt-1': log('evt-1', 100),
  'evt-2': log('evt-2', 200),
  'evt-3': log('evt-3', 300),
}

describe('selectRelatedLogs, unfocused', () => {
  it('returns nothing before the first chain extraction', () => {
    expect(selectRelatedLogs(logs, [], null, null)).toEqual([])
  })

  it('returns chain-step logs time-sorted and flagged onChain', () => {
    const out = selectRelatedLogs(logs, [], chain, null)
    expect(out.map(r => r.log.event_id)).toEqual(['evt-1', 'evt-2'])
    expect(out.every(r => r.onChain)).toBe(true)
  })

  it('skips chain steps whose log never arrived', () => {
    const sparse: ChainResultPayload = {
      confidence: 0.9,
      steps: [
        { event_id: 'evt-1', description: 'step 1', confidence: 0.9, ts: 100 },
        { event_id: 'evt-missing', description: 'no log', confidence: 0.9, ts: 150 },
      ],
    }
    const out = selectRelatedLogs(logs, [], sparse, null)
    expect(out.map(r => r.log.event_id)).toEqual(['evt-1'])
  })
})

describe('selectRelatedLogs, node focused', () => {
  const edges = [
    edge('e1', 'a', 'b', 'evt-1'),
    edge('e2', 'b', 'c', 'evt-3'),
    edge('e3', 'c', 'd', 'evt-2'),
    edge('e4', 'b', 'x'), // no source_event_id: ignored
  ]

  it('returns logs for every edge touching the node, on-chain or not', () => {
    const out = selectRelatedLogs(logs, edges, chain, 'b')
    expect(out.map(r => r.log.event_id)).toEqual(['evt-1', 'evt-3'])
  })

  it('flags which focused-node logs are on the chain', () => {
    const out = selectRelatedLogs(logs, edges, chain, 'b')
    expect(out.find(r => r.log.event_id === 'evt-1')!.onChain).toBe(true)
    expect(out.find(r => r.log.event_id === 'evt-3')!.onChain).toBe(false)
  })

  it('returns nothing for a node with no incident edges', () => {
    expect(selectRelatedLogs(logs, edges, chain, 'zzz')).toEqual([])
  })

  it('ignores the chain entirely while focused (off-chain node shows its own logs)', () => {
    const out = selectRelatedLogs(logs, edges, null, 'c')
    expect(out.map(r => r.log.event_id)).toEqual(['evt-2', 'evt-3'])
  })
})
