import { useCallback, useEffect, useMemo, useReducer, useRef } from 'react'
import { EngineSocket } from './ws'
import type { GraphUpdatePayload, ScoreUpdatePayload, ChainResultPayload, NarrationPayload, WsNode, WsEdge, LogEventPayload, ThreatIntelPayload } from './ws'
import { GraphView } from './GraphView'
import { PhasePanel } from './PhasePanel'
import { buildAttackPhases, buildTechniqueFoci } from './attackPhases'
import type { AttackPhase } from './attackPhases'
import { TimeScrubber } from './TimeScrubber'
import { DetailTabs, type DetailTab } from './DetailTabs'
import { IncidentList } from './IncidentList'
import { selectRelatedLogs } from './logFilter'
import { buildNodeContext } from './nodeContext'
import { displayRange, buildPhases } from './timeline'
import './App.css'

const WS_URL = (import.meta.env.VITE_WS_URL as string | undefined) ?? `ws://${window.location.host}/ws`

// Overlay messages without an incident_id (legacy fixtures, ai-off stubs) all
// route to this single bucket so the UI still shows one incident for them.
const LEGACY_INCIDENT_ID = 'inc-legacy'

export interface IncidentState {
  id: string
  label: string
  chain: ChainResultPayload | null
  narration: NarrationPayload | null
  threatIntel: ThreatIntelPayload | null
  firstSeen: number
  awaitingNarration: boolean
  awaitingIntel: boolean
}

export interface AppState {
  nodes: Record<string, WsNode>
  edges: Record<string, WsEdge>
  status: 'connecting' | 'live' | 'reconnecting'
  timeWindow: [number, number] | null
  logs: Record<string, LogEventPayload>
  focusedNodeId: string | null
  // Log filter for chain steps with no graph node to focus (e.g. a privilege
  // grant logged on the DC). Mutually exclusive with focusedNodeId.
  focusedEventId: string | null
  // Request for the timeline to select the event at ts; seq increments per
  // request so repeated jumps to the same ts still fire.
  timelineJump: { ts: number; seq: number } | null
  activeTab: DetailTab
  incidents: Record<string, IncidentState>
  activeIncidentId: string | null
  // Selected attack phase card (kebab-case tactic id) of the active incident.
  activeFocusId: string | null
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
  | { type: 'focus_event'; payload: string | null }
  | { type: 'jump_to_ts'; payload: number }
  | { type: 'threat_intel'; payload: ThreatIntelPayload }
  | { type: 'set_tab'; payload: DetailTab }
  | { type: 'select_incident'; payload: string }
  // showEvidence opens the Logs tab with the selection; clicks originating
  // inside a detail tab leave the user's tab alone.
  | { type: 'select_focus'; payload: { id: string; endTs: number; showEvidence?: boolean } | null }

export const initialState: AppState = {
  nodes: {},
  edges: {},
  status: 'connecting',
  timeWindow: null,
  logs: {},
  focusedNodeId: null,
  focusedEventId: null,
  timelineJump: null,
  activeTab: 'logs',
  incidents: {},
  activeIncidentId: null,
  activeFocusId: null,
}

function incidentIdOf(payload: { incident_id?: string }): string {
  return payload.incident_id ?? LEGACY_INCIDENT_ID
}

function chainFirstSeen(chain: ChainResultPayload): number {
  if (chain.steps.length === 0) return 0
  return Math.min(...chain.steps.map((s) => s.ts))
}

// Returns the incident for id, or a blank placeholder when an out-of-order
// narration/intel message arrives before its chain_result.
function incidentOrPlaceholder(state: AppState, id: string): IncidentState {
  return state.incidents[id] ?? {
    id,
    label: id,
    chain: null,
    narration: null,
    threatIntel: null,
    firstSeen: 0,
    awaitingNarration: true,
    awaitingIntel: true,
  }
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
    case 'chain_result': {
      const id = incidentIdOf(action.payload)
      const prev = state.incidents[id]
      const incident: IncidentState = {
        id,
        label: action.payload.incident_label ?? prev?.label ?? id,
        chain: action.payload,
        narration: prev?.narration ?? null,
        threatIntel: prev?.threatIntel ?? null,
        firstSeen: prev?.firstSeen ?? chainFirstSeen(action.payload),
        awaitingNarration: true,
        awaitingIntel: true,
      }
      return {
        ...state,
        incidents: { ...state.incidents, [id]: incident },
        activeIncidentId: prev ? state.activeIncidentId : id,
      }
    }
    case 'narration': {
      const id = incidentIdOf(action.payload)
      const base = incidentOrPlaceholder(state, id)
      return {
        ...state,
        incidents: {
          ...state.incidents,
          [id]: { ...base, narration: action.payload, awaitingNarration: false },
        },
      }
    }
    case 'threat_intel': {
      const id = incidentIdOf(action.payload)
      const base = incidentOrPlaceholder(state, id)
      return {
        ...state,
        incidents: {
          ...state.incidents,
          [id]: { ...base, threatIntel: action.payload, awaitingIntel: false },
        },
      }
    }
    case 'select_incident':
      // A context switch: the previous incident's focus, window, and node
      // selection do not follow into the new one.
      return {
        ...state,
        activeIncidentId: action.payload,
        activeFocusId: null,
        timeWindow: null,
        focusedNodeId: null,
        focusedEventId: null,
      }
    case 'select_focus': {
      if (action.payload === null) {
        return { ...state, activeFocusId: null, timeWindow: null }
      }
      // Selecting a phase tells the story up to that point: the window ends
      // at the phase's last event, so the graph shows the attack as of that
      // phase and the evidence below is scoped to it.
      return {
        ...state,
        activeFocusId: action.payload.id,
        timeWindow: [0, action.payload.endTs],
        focusedNodeId: null,
        focusedEventId: null,
        activeTab: action.payload.showEvidence ? 'logs' : state.activeTab,
      }
    }
    case 'connected':
      return { ...state, status: 'live' }
    case 'disconnected':
      return { ...state, status: 'reconnecting' }
    case 'set_time_window':
      return { ...state, timeWindow: action.payload }
    case 'log_event':
      return { ...state, logs: { ...state.logs, [action.payload.event_id]: action.payload } }
    case 'focus_node': {
      if (action.payload === null) {
        // Releasing the node focus returns logs and timeline to Live, the
        // same resting state a deselected phase card lands on. An active
        // phase or technique focus keeps its window.
        return {
          ...state,
          focusedNodeId: null,
          focusedEventId: null,
          timeWindow: state.activeFocusId === null ? null : state.timeWindow,
        }
      }
      return { ...state, focusedNodeId: action.payload, focusedEventId: null }
    }
    case 'focus_event':
      return { ...state, focusedEventId: action.payload, focusedNodeId: null }
    case 'jump_to_ts':
      return {
        ...state,
        timelineJump: { ts: action.payload, seq: (state.timelineJump?.seq ?? 0) + 1 },
      }
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
  const incidents = Object.values(state.incidents)
  const active = state.activeIncidentId ? state.incidents[state.activeIncidentId] ?? null : null
  const activeChain = active?.chain ?? null

  const edgeTimestamps = edges.map((e) => e.ts)
  const minTs = edgeTimestamps.length > 0 ? Math.min(...edgeTimestamps) : 0
  const maxTs = edgeTimestamps.length > 0 ? Math.max(...edgeTimestamps) : 0

  // Attack phase cards: structure from the chain, prose from the narration.
  const attackPhases = useMemo(
    () => buildAttackPhases(activeChain, edges, active?.narration ?? null),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [activeChain, state.edges, active?.narration],
  )
  // MITRE techniques as alternative entry points into the same focus slot.
  const techniqueFoci = useMemo(
    () => buildTechniqueFoci(activeChain, edges, attackPhases),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [activeChain, state.edges, attackPhases],
  )
  const activePhase = attackPhases.find((p) => p.id === state.activeFocusId) ?? null
  const activeTechnique = activePhase
    ? null
    : techniqueFoci.find((t) => t.id === state.activeFocusId) ?? null
  // The one selected investigation focus, whichever surface it came from.
  const focus = activePhase ?? activeTechnique
  const phaseFocus = useMemo(
    () => focus
      ? { id: focus.id, nodeIds: focus.nodeIds, edgeIds: focus.edgeIds, color: focus.color }
      : null,
    [focus],
  )
  // Timeline emphasis: the phase itself, or the single phase a technique
  // lives in (none when a technique spans phases).
  const activePhaseName = activePhase
    ? activePhase.title
    : activeTechnique && activeTechnique.phaseIds.length === 1
      ? attackPhases.find((p) => p.id === activeTechnique.phaseIds[0])?.title ?? null
      : null

  function handlePhaseSelect(phase: AttackPhase | null) {
    dispatch({
      type: 'select_focus',
      payload: phase === null ? null : { id: phase.id, endTs: phase.endTs, showEvidence: true },
    })
  }

  // Technique clicks come from inside the detail tabs, so the selection must
  // not yank the user off the tab they are reading.
  function handleTechniqueSelect(techniqueId: string) {
    const target = techniqueFoci.find((t) => t.techniqueId === techniqueId)
    if (!target) return
    dispatch({
      type: 'select_focus',
      payload: state.activeFocusId === target.id ? null : { id: target.id, endTs: target.endTs },
    })
  }

  // Investigation context builder for the graph's inspector drawers. The
  // view keeps one drawer per pinned node, so it asks per node id; when it
  // previews another incident's panels (minimap hover), the context is
  // computed against that incident's chain so the role text stays true.
  const getNodeContext = useCallback(
    (nodeId: string, incidentId?: string) => {
      if (incidentId && incidentId !== state.activeIncidentId) {
        const incident = state.incidents[incidentId]
        const chain = incident?.chain ?? null
        const phases = buildAttackPhases(chain, edges, incident?.narration ?? null)
        const foci = buildTechniqueFoci(chain, edges, phases)
        return buildNodeContext(nodeId, state.nodes, edges, chain, phases, foci)
      }
      return buildNodeContext(nodeId, state.nodes, edges, activeChain, attackPhases, techniqueFoci)
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [state.nodes, state.edges, state.incidents, state.activeIncidentId, activeChain, attackPhases, techniqueFoci],
  )

  const relatedLogs = selectRelatedLogs(
    state.logs, edges, activeChain, state.focusedNodeId, state.timeWindow, state.focusedEventId,
    focus?.eventIds ?? null,
  )
  const focusedStep = state.focusedEventId !== null
    ? activeChain?.steps.find((s) => s.event_id === state.focusedEventId) ?? null
    : null
  const focusedLabel = state.focusedNodeId !== null
    ? state.nodes[state.focusedNodeId]?.label ?? state.focusedNodeId
    : focusedStep !== null
      ? focusedStep.technique_name ?? focusedStep.description
      : state.focusedEventId

  // Same phase segmentation the timeline renders, so log rows can wear the
  // color of the attack phase they belong to.
  const [dispMin, dispMax] = displayRange(activeChain?.steps ?? [], minTs, maxTs)
  const phases = buildPhases(activeChain?.steps ?? [], activeChain?.tactics, dispMin, dispMax)

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
          <aside className="dash-panel incident-pane">
            <div className="dash-panel-title">Incidents</div>
            <div className="dash-panel-body">
              <IncidentList
                incidents={incidents}
                activeIncidentId={state.activeIncidentId}
                onSelect={(id) => dispatch({ type: 'select_incident', payload: id })}
              />
            </div>
          </aside>
          <section className="dash-panel graph-pane">
            <div className="dash-panel-title">Provenance Graph</div>
            <div className="dash-panel-body">
              <GraphView
                nodes={nodes}
                edges={edges}
                chain={activeChain}
                timeWindow={state.timeWindow}
                focusedNodeId={state.focusedNodeId}
                onNodeFocus={(id) => dispatch({ type: 'focus_node', payload: id })}
                incidents={incidents}
                activeIncidentId={state.activeIncidentId}
                onIncidentSelect={(id) => dispatch({ type: 'select_incident', payload: id })}
                phaseFocus={phaseFocus}
                getNodeContext={getNodeContext}
                onPhaseSelect={handlePhaseSelect}
                onTechniqueSelect={handleTechniqueSelect}
              />
              {edges.length > 0 && (
                <TimeScrubber
                  minTs={minTs}
                  maxTs={maxTs}
                  window={state.timeWindow}
                  edges={edges}
                  chain={activeChain}
                  jump={state.timelineJump}
                  activePhaseName={activePhaseName}
                  onChange={(w) => dispatch({ type: 'set_time_window', payload: w })}
                  onEventFocus={(nodeId, eventId) => {
                    if (nodeId !== null) {
                      dispatch({ type: 'focus_node', payload: nodeId })
                      dispatch({ type: 'set_tab', payload: 'logs' })
                    } else if (eventId != null) {
                      dispatch({ type: 'focus_event', payload: eventId })
                      dispatch({ type: 'set_tab', payload: 'logs' })
                    } else {
                      dispatch({ type: 'focus_node', payload: null })
                    }
                  }}
                />
              )}
            </div>
          </section>
          <aside className="dash-panel narration-pane">
            <div className="dash-panel-title">Attack Phases</div>
            <div className="dash-panel-body narration-pane-body">
              <PhasePanel
                phases={attackPhases}
                activeFocusId={state.activeFocusId}
                activeTechnique={activeTechnique}
                narration={active?.narration ?? null}
                awaitingNarration={active?.awaitingNarration ?? false}
                onPhaseSelect={handlePhaseSelect}
              />
            </div>
          </aside>
        </div>
        <DetailTabs
          activeTab={state.activeTab}
          onTabChange={(tab) => dispatch({ type: 'set_tab', payload: tab })}
          logs={relatedLogs}
          phases={phases}
          onLogSelect={(log) => dispatch({ type: 'jump_to_ts', payload: log.ts })}
          focusedLabel={focusedLabel}
          hasChain={activeChain !== null}
          onClearFocus={() => dispatch({ type: 'focus_node', payload: null })}
          chain={activeChain}
          edges={edges}
          intel={active?.threatIntel ?? null}
          awaitingIntel={active?.awaitingIntel ?? false}
          onNodeFocus={(id) => dispatch({ type: 'focus_node', payload: id })}
          onTechniqueSelect={handleTechniqueSelect}
          activeTechniqueId={activeTechnique?.techniqueId ?? null}
          chainTechniqueIds={techniqueFoci.map((t) => t.techniqueId)}
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
