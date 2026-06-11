import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest'
import {
  EngineSocket,
  type MessageHandlers,
  type GraphUpdatePayload,
  type ScoreUpdatePayload,
  type ChainResultPayload,
  type NarrationPayload,
  type LogEventPayload,
  type ThreatIntelPayload,
} from '../ws'

// Fake WebSocket - no DOM, no real network.
class FakeWebSocket {
  static instances: FakeWebSocket[] = []

  onopen: ((event: Event) => void) | null = null
  onmessage: ((event: MessageEvent) => void) | null = null
  onclose: ((event: CloseEvent) => void) | null = null
  onerror: ((event: Event) => void) | null = null
  readonly url: string
  closed = false

  constructor(url: string) {
    this.url = url
    FakeWebSocket.instances.push(this)
  }

  close() {
    this.closed = true
    this.onclose?.(new CloseEvent('close'))
  }

  // Test helpers
  open() { this.onopen?.(new Event('open')) }
  drop() { this.onclose?.(new CloseEvent('close')) }
  send(data: unknown) {
    this.onmessage?.(new MessageEvent('message', { data: JSON.stringify(data) }))
  }
}

function fakeFactory(): [(url: string) => WebSocket, () => FakeWebSocket[]] {
  const instances: FakeWebSocket[] = []
  const factory = (url: string) => {
    const ws = new FakeWebSocket(url)
    instances.push(ws)
    return ws as unknown as WebSocket
  }
  return [factory, () => instances]
}

function makeHandlers(): MessageHandlers & {
  graphUpdates: GraphUpdatePayload[]
  scoreUpdates: ScoreUpdatePayload[]
  chainResults: ChainResultPayload[]
  narrations: NarrationPayload[]
  logEvents: LogEventPayload[]
  threatIntels: ThreatIntelPayload[]
} {
  const graphUpdates: GraphUpdatePayload[] = []
  const scoreUpdates: ScoreUpdatePayload[] = []
  const chainResults: ChainResultPayload[] = []
  const narrations: NarrationPayload[] = []
  const logEvents: LogEventPayload[] = []
  const threatIntels: ThreatIntelPayload[] = []
  return {
    graphUpdates,
    scoreUpdates,
    chainResults,
    narrations,
    logEvents,
    threatIntels,
    onGraphUpdate(p) { graphUpdates.push(p) },
    onScoreUpdate(p) { scoreUpdates.push(p) },
    onChainResult(p) { chainResults.push(p) },
    onNarration(p) { narrations.push(p) },
    onLogEvent(p) { logEvents.push(p) },
    onThreatIntel(p) { threatIntels.push(p) },
  }
}

beforeEach(() => {
  FakeWebSocket.instances.length = 0
})

afterEach(() => {
  vi.useRealTimers()
})

describe('EngineSocket message dispatch', () => {
  it('calls onGraphUpdate with the correct payload', () => {
    const [factory, getInstances] = fakeFactory()
    const handlers = makeHandlers()
    const sock = new EngineSocket('ws://localhost:8080/ws', handlers, factory)
    sock.connect()

    const payload: GraphUpdatePayload = {
      nodes: [{ id: 'proc-1', kind: 'Process', label: 'cmd.exe', attrs: { pid: 1 } }],
      edges: [{ id: 'e1', src: 'proc-0', dst: 'proc-1', kind: 'spawned', ts: 1749100000, confidence: 0.9 }],
    }
    getInstances()[0].send({ type: 'graph_update', payload })

    expect(handlers.graphUpdates).toHaveLength(1)
    expect(handlers.graphUpdates[0]).toEqual(payload)

    sock.close()
  })

  it('calls onScoreUpdate with the correct payload', () => {
    const [factory, getInstances] = fakeFactory()
    const handlers = makeHandlers()
    const sock = new EngineSocket('ws://localhost:8080/ws', handlers, factory)
    sock.connect()

    const payload: ScoreUpdatePayload = { edge_id: 'e1', score: 0.87 }
    getInstances()[0].send({ type: 'score_update', payload })

    expect(handlers.scoreUpdates).toHaveLength(1)
    expect(handlers.scoreUpdates[0]).toEqual(payload)

    sock.close()
  })

  it('calls onChainResult with the correct payload', () => {
    const [factory, getInstances] = fakeFactory()
    const handlers = makeHandlers()
    const sock = new EngineSocket('ws://localhost:8080/ws', handlers, factory)
    sock.connect()

    const payload: ChainResultPayload = {
      confidence: 0.91,
      steps: [
        { event_id: 'evt-001', description: 'cmd.exe spawned powershell.exe', confidence: 0.95, ts: 1749100000 },
      ],
    }
    getInstances()[0].send({ type: 'chain_result', payload })

    expect(handlers.chainResults).toHaveLength(1)
    expect(handlers.chainResults[0]).toEqual(payload)

    sock.close()
  })

  it('calls onNarration with the correct payload', () => {
    const [factory, getInstances] = fakeFactory()
    const handlers = makeHandlers()
    const sock = new EngineSocket('ws://localhost:8080/ws', handlers, factory)
    sock.connect()

    const payload: NarrationPayload = {
      text: 'PowerShell accessed LSASS.',
      hypotheses: ['Credentials exfiltrated before network telemetry began'],
      actions: ['Isolate WS01'],
    }
    getInstances()[0].send({ type: 'narration', payload })

    expect(handlers.narrations).toHaveLength(1)
    expect(handlers.narrations[0]).toEqual(payload)

    sock.close()
  })

  it('calls onLogEvent with the correct payload', () => {
    const [factory, getInstances] = fakeFactory()
    const handlers = makeHandlers()
    const sock = new EngineSocket('ws://localhost:8080/ws', handlers, factory)
    sock.connect()

    const payload: LogEventPayload = {
      event_id: 'evt-001',
      ts: 1749100030,
      source: 'sysmon',
      raw: { EventID: '1', Image: 'C:\\Windows\\powershell.exe', host: 'WS01' },
    }
    getInstances()[0].send({ type: 'log_event', payload })

    expect(handlers.logEvents).toHaveLength(1)
    expect(handlers.logEvents[0]).toEqual(payload)

    sock.close()
  })

  it('ignores unknown message types without throwing', () => {
    const [factory, getInstances] = fakeFactory()
    const handlers = makeHandlers()
    const sock = new EngineSocket('ws://localhost:8080/ws', handlers, factory)
    sock.connect()

    expect(() => {
      getInstances()[0].send({ type: 'totally_unknown', payload: {} })
    }).not.toThrow()

    expect(handlers.graphUpdates).toHaveLength(0)
    expect(handlers.scoreUpdates).toHaveLength(0)
    expect(handlers.chainResults).toHaveLength(0)
    expect(handlers.narrations).toHaveLength(0)

    sock.close()
  })

  it('calls onThreatIntel with the correct payload', () => {
    const [factory, getInstances] = fakeFactory()
    const handlers = makeHandlers()
    const sock = new EngineSocket('ws://localhost:8080/ws', handlers, factory)
    sock.connect()
    getInstances()[0].send({
      type: 'threat_intel',
      payload: { status: 'ok', summary: 's', techniques: [], cve_matches: [] },
    })
    expect(handlers.threatIntels.length).toBe(1)
    expect(handlers.threatIntels[0].summary).toBe('s')
  })
})

describe('EngineSocket reconnect', () => {
  it('opens a new WebSocket after connection drop', () => {
    vi.useFakeTimers()
    const [factory, getInstances] = fakeFactory()
    const handlers = makeHandlers()
    const sock = new EngineSocket('ws://localhost:8080/ws', handlers, factory)
    sock.connect()

    expect(getInstances()).toHaveLength(1)

    // Simulate an unexpected drop (not a call to sock.close())
    getInstances()[0].drop()

    // Advance past the initial 1s retry delay
    vi.advanceTimersByTime(1_100)

    expect(getInstances()).toHaveLength(2)
    expect(getInstances()[1].url).toBe('ws://localhost:8080/ws')

    sock.close()
  })

  it('does not reconnect after intentional close', () => {
    vi.useFakeTimers()
    const [factory, getInstances] = fakeFactory()
    const handlers = makeHandlers()
    const sock = new EngineSocket('ws://localhost:8080/ws', handlers, factory)
    sock.connect()

    sock.close()
    vi.advanceTimersByTime(5_000)

    // Still only the original WebSocket, no retry
    expect(getInstances()).toHaveLength(1)
  })
})
