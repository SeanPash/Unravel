// WebSocket client for the Causal Reconstruction Engine.
// Plain class (not a React hook) so it can be unit tested without a DOM.

export interface WsNode {
  id: string
  kind: 'Process' | 'Host' | 'User' | 'NetFlow'
  label: string
  attrs: Record<string, unknown>
}

export interface WsEdge {
  id: string
  src: string
  dst: string
  kind: string
  ts: number
  confidence: number
  source_event_id?: string
}

export interface GraphUpdatePayload {
  nodes: WsNode[]
  edges: WsEdge[]
}

export interface ScoreUpdatePayload {
  edge_id: string
  score: number
}

export interface ChainStep {
  event_id: string
  description: string
  confidence: number
  ts: number
  technique_id?: string
  technique_name?: string
  tactic?: string
}

export interface ChainResultPayload {
  incident_id?: string
  incident_label?: string
  confidence: number
  steps: ChainStep[]
  tactics?: string[]
}

export interface ThreatIntelTechnique {
  id: string
  name: string
  groups: string[]
  software: string[]
  mitigations: string[]
}

export interface CVEMatch {
  id: string
  summary: string
  in_kev: boolean
  severity?: string
}

export interface ThreatIntelPayload {
  incident_id?: string
  status: string
  summary: string
  techniques: ThreatIntelTechnique[]
  cve_matches?: CVEMatch[]
}

// Per-phase AI enrichment. The narrator only writes prose; the structural
// truth of a phase (nodes, edges, timestamps, confidence) is derived from the
// chain by the engine and never by the model.
export interface NarrationPhase {
  id: string
  title: string
  summary: string
}

export interface NarrationPayload {
  incident_id?: string
  text: string
  hypotheses: string[]
  actions: string[]
  phases?: NarrationPhase[]
}

export interface LogEventPayload {
  event_id: string
  ts: number
  source: string
  raw: Record<string, unknown>
}

export interface MessageHandlers {
  onGraphUpdate(payload: GraphUpdatePayload): void
  onScoreUpdate(payload: ScoreUpdatePayload): void
  onChainResult(payload: ChainResultPayload): void
  onNarration(payload: NarrationPayload): void
  onLogEvent?(payload: LogEventPayload): void
  onThreatIntel?(payload: ThreatIntelPayload): void
  onOpen?(): void
  onClose?(): void
}

const INITIAL_RETRY_MS = 1_000
const MAX_RETRY_MS = 30_000

export class EngineSocket {
  private readonly url: string
  private readonly handlers: MessageHandlers
  private readonly wsFactory: (url: string) => WebSocket

  private ws: WebSocket | null = null
  private intentionallyClosed = false
  private retryDelay = INITIAL_RETRY_MS
  private retryTimer: ReturnType<typeof setTimeout> | null = null

  constructor(
    url: string,
    handlers: MessageHandlers,
    wsFactory?: (url: string) => WebSocket,
  ) {
    this.url = url
    this.handlers = handlers
    this.wsFactory = wsFactory ?? ((u) => new WebSocket(u))
  }

  connect(): void {
    this.intentionallyClosed = false
    this.retryDelay = INITIAL_RETRY_MS
    this._open()
  }

  close(): void {
    this.intentionallyClosed = true
    if (this.retryTimer !== null) {
      clearTimeout(this.retryTimer)
      this.retryTimer = null
    }
    this.ws?.close()
    this.ws = null
  }

  private _open(): void {
    const ws = this.wsFactory(this.url)
    this.ws = ws

    ws.onopen = () => {
      this.retryDelay = INITIAL_RETRY_MS
      this.handlers.onOpen?.()
    }

    ws.onmessage = (event: MessageEvent) => {
      let msg: { type: string; payload: unknown }
      try {
        msg = JSON.parse(event.data as string) as { type: string; payload: unknown }
      } catch {
        console.warn('[EngineSocket] unparseable message')
        return
      }
      this._dispatch(msg.type, msg.payload)
    }

    ws.onclose = () => {
      if (this.intentionallyClosed) return
      this.handlers.onClose?.()
      this.retryTimer = setTimeout(() => {
        this.retryDelay = Math.min(this.retryDelay * 2, MAX_RETRY_MS)
        this._open()
      }, this.retryDelay)
    }

    ws.onerror = () => {
      console.error('[EngineSocket] WebSocket error')
    }
  }

  private _dispatch(type: string, payload: unknown): void {
    switch (type) {
      case 'graph_update':
        this.handlers.onGraphUpdate(payload as GraphUpdatePayload)
        break
      case 'score_update':
        this.handlers.onScoreUpdate(payload as ScoreUpdatePayload)
        break
      case 'chain_result':
        this.handlers.onChainResult(payload as ChainResultPayload)
        break
      case 'narration':
        this.handlers.onNarration(payload as NarrationPayload)
        break
      case 'log_event':
        this.handlers.onLogEvent?.(payload as LogEventPayload)
        break
      case 'threat_intel':
        this.handlers.onThreatIntel?.(payload as ThreatIntelPayload)
        break
      default:
        console.warn('[EngineSocket] unknown message type:', type)
    }
  }
}
