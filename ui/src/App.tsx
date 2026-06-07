import { useEffect, useReducer, useRef } from 'react'
import { EngineSocket } from './ws'
import type { GraphUpdatePayload, ScoreUpdatePayload, ChainResultPayload, NarrationPayload, WsNode, WsEdge } from './ws'
import { GraphView } from './GraphView'
import { NarrationPanel } from './NarrationPanel'
import { TimeScrubber } from './TimeScrubber'
import './App.css'

const WS_URL = (import.meta.env.VITE_WS_URL as string | undefined) ?? `ws://${window.location.host}/ws`

interface AppState {
  nodes: Record<string, WsNode>
  edges: Record<string, WsEdge>
  chain: ChainResultPayload | null
  narration: NarrationPayload | null
  status: 'connecting' | 'live' | 'reconnecting'
  awaitingNarration: boolean
  timeWindow: [number, number] | null
}

type Action =
  | { type: 'graph_update'; payload: GraphUpdatePayload }
  | { type: 'score_update'; payload: ScoreUpdatePayload }
  | { type: 'chain_result'; payload: ChainResultPayload }
  | { type: 'narration'; payload: NarrationPayload }
  | { type: 'connected' }
  | { type: 'disconnected' }
  | { type: 'set_time_window'; payload: [number, number] | null }

const initialState: AppState = {
  nodes: {},
  edges: {},
  chain: null,
  narration: null,
  status: 'connecting',
  awaitingNarration: false,
  timeWindow: null,
}

function reducer(state: AppState, action: Action): AppState {
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
      return { ...state, chain: action.payload, awaitingNarration: true }
    case 'narration':
      return { ...state, narration: action.payload, awaitingNarration: false }
    case 'connected':
      return { ...state, status: 'live' }
    case 'disconnected':
      return { ...state, status: 'reconnecting' }
    case 'set_time_window':
      return { ...state, timeWindow: action.payload }
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

  return (
    <div className="app">
      <header className="app-header">
        <span className="app-title">Causal Reconstruction Engine</span>
        <StatusBadge status={state.status} />
      </header>
      <main className="app-main">
        <section className="graph-pane">
          <GraphView
            nodes={nodes}
            edges={edges}
            chain={state.chain}
            timeWindow={state.timeWindow}
          />
          {edges.length > 0 && (
            <TimeScrubber
              minTs={minTs}
              maxTs={maxTs}
              window={state.timeWindow}
              onChange={(w) => dispatch({ type: 'set_time_window', payload: w })}
            />
          )}
        </section>
        <aside className="narration-pane">
          <NarrationPanel narration={state.narration} awaitingNarration={state.awaitingNarration} />
        </aside>
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
