import { useEffect, useReducer, useRef } from 'react'
import { EngineSocket } from './ws'
import type { GraphUpdatePayload, ScoreUpdatePayload, ChainResultPayload, NarrationPayload, WsNode, WsEdge, LogEventPayload, ThreatIntelPayload } from './ws'
import { GraphView } from './GraphView'
import { NarrationPanel } from './NarrationPanel'
import { TimeScrubber } from './TimeScrubber'
import { DetailTabs, type DetailTab } from './DetailTabs'
import { selectRelatedLogs } from './logFilter'
import './App.css'

const WS_URL = (import.meta.env.VITE_WS_URL as string | undefined) ?? `ws://${window.location.host}/ws`

export interface AppState {
  nodes: Record<string, WsNode>
  edges: Record<string, WsEdge>
  chain: ChainResultPayload | null
  narration: NarrationPayload | null
  status: 'connecting' | 'live' | 'reconnecting'
  awaitingNarration: boolean
  timeWindow: [number, number] | null
  logs: Record<string, LogEventPayload>
  focusedNodeId: string | null
  threatIntel: ThreatIntelPayload | null
  awaitingIntel: boolean
  activeTab: DetailTab
}

export type Action =
  | { type: 'graph_update'; payload: GraphUpdatePayload }
  | { type: 'score_update'; payload: ScoreUpdatePayload }
  | { type: 'chain_result'; payload: ChainResultPayload }
  | { type: 'narration'; payload: NarrationPayload }
  | { type: 'connected' }
  | { type: 'disconnected' }
  | { type: 'set_time_window'; payload: [number, number] | null }
  | { type: 'log_event'; payload: LogEventPayload }
  | { type: 'focus_node'; payload: string | null }
  | { type: 'threat_intel'; payload: ThreatIntelPayload }
  | { type: 'set_tab'; payload: DetailTab }

export const initialState: AppState = {
  nodes: {},
  edges: {},
  chain: null,
  narration: null,
  status: 'connecting',
  awaitingNarration: false,
  timeWindow: null,
  logs: {},
  focusedNodeId: null,
  threatIntel: null,
  awaitingIntel: false,
  activeTab: 'logs',
}

export function reducer(state: AppState, action: Action): AppState {
  switch (action.type) {
    case 'graph_update': {
      const nodes = { ...state.nodes }
      for (const n of action.payload.nodes) nodes[n.id] = n
      const edges = { ...state.edges }
      for (const e of action.payload.edges) edges[e.id] = e
      return { ...state, nodes, edges }
    }
    case 'score_update': {
      const edge = state.edges[action.payload.edge_id]
      if (!edge) return state
      return {
        ...state,
        edges: {
          ...state.edges,
          [action.payload.edge_id]: { ...edge, confidence: action.payload.score },
        },
      }
    }
    case 'chain_result':
      return { ...state, chain: action.payload, awaitingNarration: true, awaitingIntel: true }
    case 'narration':
      return { ...state, narration: action.payload, awaitingNarration: false }
    case 'connected':
      return { ...state, status: 'live' }
    case 'disconnected':
      return { ...state, status: 'reconnecting' }
    case 'set_time_window':
      return { ...state, timeWindow: action.payload }
    case 'log_event':
      return { ...state, logs: { ...state.logs, [action.payload.event_id]: action.payload } }
    case 'focus_node':
      return { ...state, focusedNodeId: action.payload }
    case 'threat_intel':
      return { ...state, threatIntel: action.payload, awaitingIntel: false }
    case 'set_tab':
      return { ...state, activeTab: action.payload }
  }
}

export default function App() {
  const [state, dispatch] = useReducer(reducer, initialState)
  const socketRef = useRef<EngineSocket | null>(null)

  useEffect(() => {
    const sock = new EngineSocket(WS_URL, {
      onGraphUpdate: (p) => dispatch({ type: 'graph_update', payload: p }),
      onScoreUpdate: (p) => dispatch({ type: 'score_update', payload: p }),
      onChainResult: (p) => dispatch({ type: 'chain_result', payload: p }),
      onNarration: (p) => dispatch({ type: 'narration', payload: p }),
      onLogEvent: (p) => dispatch({ type: 'log_event', payload: p }),
      onThreatIntel: (p) => dispatch({ type: 'threat_intel', payload: p }),
      onOpen: () => dispatch({ type: 'connected' }),
      onClose: () => dispatch({ type: 'disconnected' }),
    })
    socketRef.current = sock
    sock.connect()
    return () => { sock.close() }
  }, [])

  const nodes = Object.values(state.nodes)
  const edges = Object.values(state.edges)

  const edgeTimestamps = edges.map(e => e.ts)
  const minTs = edgeTimestamps.length > 0 ? Math.min(...edgeTimestamps) : 0
  const maxTs = edgeTimestamps.length > 0 ? Math.max(...edgeTimestamps) : 0

  const relatedLogs = selectRelatedLogs(state.logs, edges, state.chain, state.focusedNodeId)
  const focusedLabel = state.focusedNodeId !== null
    ? state.nodes[state.focusedNodeId]?.label ?? state.focusedNodeId
    : null

  return (
    <div className="app">
      <header className="app-bar">
        <div className="app-bar-brand">
          <span className="app-bar-logo">
            splunk<span className="app-bar-logo-caret">&gt;</span>
          </span>
          <span className="app-title">Causal Reconstruction Engine</span>
        </div>
        <StatusBadge status={state.status} />
      </header>
      <main className="app-main">
        <div className="app-main-row">
          <section className="dash-panel graph-pane">
            <div className="dash-panel-title">Provenance Graph</div>
            <div className="dash-panel-body">
              <GraphView
                nodes={nodes}
                edges={edges}
                chain={state.chain}
                timeWindow={state.timeWindow}
                focusedNodeId={state.focusedNodeId}
                onNodeFocus={(id) => dispatch({ type: 'focus_node', payload: id })}
              />
              {edges.length > 0 && (
                <TimeScrubber
                  minTs={minTs}
                  maxTs={maxTs}
                  window={state.timeWindow}
                  edges={edges}
                  onChange={(w) => dispatch({ type: 'set_time_window', payload: w })}
                />
              )}
            </div>
          </section>
          <aside className="dash-panel narration-pane">
            <div className="dash-panel-title">AI Narration</div>
            <div className="dash-panel-body narration-pane-body">
              <NarrationPanel narration={state.narration} awaitingNarration={state.awaitingNarration} />
            </div>
          </aside>
        </div>
        <DetailTabs
          activeTab={state.activeTab}
          onTabChange={(tab) => dispatch({ type: 'set_tab', payload: tab })}
          logs={relatedLogs}
          focusedLabel={focusedLabel}
          hasChain={state.chain !== null}
          onClearFocus={() => dispatch({ type: 'focus_node', payload: null })}
          chain={state.chain}
          edges={edges}
          intel={state.threatIntel}
          awaitingIntel={state.awaitingIntel}
          onNodeFocus={(id) => dispatch({ type: 'focus_node', payload: id })}
        />
      </main>
    </div>
  )
}

const STATUS_LABELS: Record<AppState['status'], string> = {
  connecting: 'Connecting...',
  live: 'Live',
  reconnecting: 'Reconnecting...',
}

function StatusBadge({ status }: { status: AppState['status'] }) {
  return (
    <span className={`status-badge status-${status}`}>
      {STATUS_LABELS[status]}
    </span>
  )
}
