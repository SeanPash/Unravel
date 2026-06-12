import { useRef, useEffect, useState, useCallback } from 'react'
import cytoscape from 'cytoscape'
import cola from 'cytoscape-cola'
import type { Core } from 'cytoscape'
import type { WsNode, WsEdge, ChainResultPayload } from './ws'
import { assignIncidents, sectionSlot } from './incidentMap'
import type { IncidentRef, IncidentAssignment } from './incidentMap'
import { Minimap } from './Minimap'
import type { MinimapData } from './Minimap'
import { NodeInspector } from './NodeInspector'
import type { NodeContext } from './nodeContext'
import type { AttackPhase } from './attackPhases'

cytoscape.use(cola)

export interface GraphViewProps {
  nodes: WsNode[]
  edges: WsEdge[]
  chain: ChainResultPayload | null
  timeWindow?: [number, number] | null
  focusedNodeId?: string | null
  onNodeFocus?: (nodeId: string | null) => void
  // Incident map: each incident's subgraph lives in its own labeled section
  // of the canvas; selecting an incident flies the camera to its section.
  incidents?: IncidentRef[]
  activeIncidentId?: string | null
  onIncidentSelect?: (incidentId: string) => void
  // Selected attack phase: its members light up in the phase color, the rest
  // of the graph fades back, and the camera frames the phase subgraph.
  phaseFocus?: PhaseFocus | null
  // Builds the investigation context for any node id, so the view can keep
  // several inspector drawers open at once. Chip and relation clicks route
  // back into the app's focus machinery via the two select callbacks.
  getNodeContext?: (nodeId: string) => NodeContext | null
  onPhaseSelect?: (phase: AttackPhase) => void
  onTechniqueSelect?: (techniqueId: string) => void
}

export interface PhaseFocus {
  id: string
  nodeIds: string[]
  edgeIds: string[]
  color: string
}

// --- Pure helpers (exported for unit tests) ---

function hexToRgb(hex: string): [number, number, number] {
  return [
    parseInt(hex.slice(1, 3), 16),
    parseInt(hex.slice(3, 5), 16),
    parseInt(hex.slice(5, 7), 16),
  ]
}

function lerpColor(a: string, b: string, t: number): string {
  const [r1, g1, b1] = hexToRgb(a)
  const [r2, g2, b2] = hexToRgb(b)
  const r = Math.round(r1 + (r2 - r1) * t)
  const g = Math.round(g1 + (g2 - g1) * t)
  const bv = Math.round(b1 + (b2 - b1) * t)
  return `rgb(${r}, ${g}, ${bv})`
}

// Maps suspicion score 0-1 to a color: muted slate -> Splunk amber. Red is
// deliberately absent so the attack-chain highlight owns it outright.
export function scoreToColor(score: number): string {
  const s = Math.max(0, Math.min(1, score))
  return lerpColor('#6e7c8c', '#f8be34', s)
}

// Node kind palette. Red is reserved for the chain highlight, so no kind
// uses it. The legend renders from this map so the two cannot drift.
export const KIND_COLORS: Record<WsNode['kind'], string> = {
  Process: '#53a051',
  Host: '#4fa7d9',
  User: '#f8be34',
  NetFlow: '#9d7cd8',
}

export function kindToColor(kind: WsNode['kind']): string {
  return KIND_COLORS[kind] ?? '#8c9bab'
}

export function degreeToSize(degree: number): number {
  const d = Math.max(0, degree)
  return Math.min(16 + 6 * Math.sqrt(d), 52)
}

export type LabelClass = 'labels-off' | 'labels-faint' | 'labels-on'

// Configurable zoom thresholds for label rendering. Below `off`, node labels
// hide entirely except hovered, focused, and attack-path nodes. Between `off`
// and `full`, nodes show shortened labels. At `full` and above, full labels.
export interface LabelZoomThresholds {
  off: number
  full: number
}

export const LABEL_ZOOM_THRESHOLDS: LabelZoomThresholds = { off: 0.5, full: 1.0 }

export function zoomToLabelClass(
  zoom: number,
  t: LabelZoomThresholds = LABEL_ZOOM_THRESHOLDS,
): LabelClass {
  if (zoom < t.off) return 'labels-off'
  if (zoom < t.full) return 'labels-faint'
  return 'labels-on'
}

// Graph-friendly display name: DOMAIN\user reduces to user and paths reduce
// to their basename. NORTHPOLE\Administrator -> Administrator,
// C:\...\v1.0\powershell.exe -> powershell.exe. The raw label is never
// rendered on the canvas; tooltips and detail panels keep it.
export function shortenNodeLabel(label: string): string {
  const segments = label.split(/[\\/]/)
  return segments[segments.length - 1] || label
}

// Three-character code rendered under nodes at mid zoom so labels stay
// outside the chain: WINWORD.EXE -> WIN, lsass.exe -> LSA,
// Administrator -> ADM. A trailing digit run survives with leading zeros
// dropped so host numbering stays meaningful: DC01 -> DC1.
export function abbreviateLabel(label: string): string {
  const base = shortenNodeLabel(label).replace(/\.[A-Za-z0-9]+$/, '')
  const up = base.toUpperCase()
  if (up.length <= 3) return up
  const m = up.match(/^(.*?)(\d+)$/)
  if (m) {
    const digits = String(parseInt(m[2], 10))
    const letters = m[1].slice(0, Math.max(1, 3 - digits.length))
    return (letters + digits).slice(0, 3)
  }
  return up.slice(0, 3)
}

// Counts how many edges touch each node id (both endpoints).
export function computeDegrees(edges: WsEdge[]): Map<string, number> {
  const degrees = new Map<string, number>()
  for (const e of edges) {
    degrees.set(e.src, (degrees.get(e.src) ?? 0) + 1)
    degrees.set(e.dst, (degrees.get(e.dst) ?? 0) + 1)
  }
  return degrees
}

// Returns the set of edge timestamps that are part of the chain
export function chainTimestamps(chain: ChainResultPayload | null): Set<number> {
  if (!chain) return new Set()
  return new Set(chain.steps.map(s => s.ts))
}

// --- Edge lengths ---
// Edges stretch so their relationship label fits between the endpoints: the
// cola layout is asked for a per-edge length sized to the text, capped so a
// very long kind cannot blow the layout apart. Width math assumes the 9px
// JetBrains Mono set in CY_STYLE.

const EDGE_LABEL_FONT_PX = 9
const EDGE_LABEL_CHAR_W = EDGE_LABEL_FONT_PX * 0.62
// Keeps labels clear of the node bodies and the arrowhead at both ends.
const EDGE_LABEL_CLEARANCE = 30
// The fixed cola edgeLength this graph used before; short labels do not
// shrink edges below it.
const EDGE_LENGTH_MIN = 110
const EDGE_LENGTH_MAX = 230
// Extra room so a label still reads when the simulation compresses the edge.
const EDGE_LENGTH_LABEL_ALLOWANCE = 26

export function desiredEdgeLength(kind: string): number {
  const textWidth = (kind.replace(/_/g, ' ').length + 1) * EDGE_LABEL_CHAR_W
  return Math.max(
    EDGE_LENGTH_MIN,
    Math.min(textWidth + EDGE_LABEL_CLEARANCE + EDGE_LENGTH_LABEL_ALLOWANCE, EDGE_LENGTH_MAX),
  )
}

// --- Cytoscape stylesheet ---
// Everything is driven by element data and classes; no per-element style
// bypasses anywhere, or they would override the .dim hover fade.
//
// Cytoscape cannot read CSS custom properties - all colors are hardcoded hex
// matching the design tokens in index.css.
// --bg-panel = #12171c, --bg-page = #0c0d10

const CY_STYLE = [
  // Base node: label layout shared by all nodes. Sizing and fill live on the
  // :childless rule so incident-section compounds can auto-size to their
  // children. Per-kind rules below override fill.
  {
    selector: 'node',
    style: {
      // Label: 3-char code by default; the labels-on band swaps in the
      // concise display name (basename only, never the raw path or
      // DOMAIN\user). Positioned below the node with clear spacing.
      'label': 'data(abbrev)',
      'font-size': 10,
      'font-family': '"JetBrains Mono", "Fira Code", monospace',
      'color': '#c8d2da',
      'text-opacity': 0,
      'text-valign': 'bottom',
      'text-halign': 'center',
      'text-margin-y': 12,
      // Outline halo instead of a rectangular plate - blends with graph
      'text-background-opacity': 0,
      'text-outline-color': '#12171c',
      'text-outline-width': 2,
      'text-outline-opacity': 0.9,
      'transition-property': 'opacity, text-opacity, border-opacity',
      'transition-duration': 150,
    },
  },
  // Leaf nodes: spheres sized by degree. Compounds get their own block below.
  {
    selector: 'node:childless',
    style: {
      'shape': 'ellipse',
      'background-color': '#53a051',
      'background-opacity': 0.92,
      'width': (ele: cytoscape.NodeSingular) => degreeToSize((ele.data('degree') as number) ?? 0),
      'height': (ele: cytoscape.NodeSingular) => degreeToSize((ele.data('degree') as number) ?? 0),
      // Outer glow ring: same hue as fill at low opacity for depth
      'border-width': 3,
      'border-color': '#53a051',
      'border-opacity': 0.22,
      'border-style': 'solid',
    },
  },
  // Per-kind radial gradients: lighter center -> darker edge for sphere look
  {
    selector: 'node[kind="Process"]',
    style: {
      'background-fill': 'radial-gradient',
      'background-gradient-stop-colors': '#72c070 #3d8840',
      'background-gradient-stop-positions': '28 100',
      'border-color': '#53a051',
    },
  },
  {
    selector: 'node[kind="Host"]',
    style: {
      'background-fill': 'radial-gradient',
      'background-gradient-stop-colors': '#72c2e8 #2e7faa',
      'background-gradient-stop-positions': '28 100',
      'border-color': '#4fa7d9',
    },
  },
  {
    selector: 'node[kind="User"]',
    style: {
      'background-fill': 'radial-gradient',
      'background-gradient-stop-colors': '#ffd55e #c89010',
      'background-gradient-stop-positions': '28 100',
      'border-color': '#f8be34',
    },
  },
  {
    selector: 'node[kind="NetFlow"]',
    style: {
      'background-fill': 'radial-gradient',
      'background-gradient-stop-colors': '#ba9af5 #7b52b0',
      'background-gradient-stop-positions': '28 100',
      'border-color': '#9d7cd8',
    },
  },
  {
    selector: 'edge',
    style: {
      'width': 1.5,
      'line-color': (ele: cytoscape.EdgeSingular) => scoreToColor((ele.data('confidence') as number) ?? 0.5),
      'target-arrow-color': (ele: cytoscape.EdgeSingular) => scoreToColor((ele.data('confidence') as number) ?? 0.5),
      'target-arrow-shape': 'triangle',
      'arrow-scale': 0.65,
      'curve-style': 'bezier',
      // Relationship label, hidden by default to keep the graph scannable.
      // Hover, pinning, or attack-chain membership reveals the full text,
      // floated above the line with a soft halo (no box) for legibility.
      'label': (ele: cytoscape.EdgeSingular) => ((ele.data('kind') as string) ?? '').replace(/_/g, ' '),
      'font-size': EDGE_LABEL_FONT_PX,
      'font-family': '"JetBrains Mono", "Fira Code", monospace',
      'color': '#b9c6d2',
      'text-rotation': 'autorotate',
      'text-margin-y': -8,
      'text-opacity': 0,
      'text-outline-color': '#0c0d10',
      'text-outline-width': 2.5,
      'text-outline-opacity': 0.95,
      'transition-property': 'opacity, text-opacity, width',
      'transition-duration': 150,
    },
  },
  // Node label zoom bands: hidden far out, 3-char codes at mid zoom, concise
  // display names up close. The raw label never renders on the canvas.
  // Hovered and focused nodes override the hidden band via the selectors
  // further down.
  { selector: 'node.labels-faint', style: { 'text-opacity': 0.7 } },
  { selector: 'node.labels-on', style: { 'text-opacity': 0.95, 'label': 'data(shortLabel)' } },
  {
    selector: 'edge.chain',
    style: {
      'line-color': '#dc4e41',
      'target-arrow-color': '#dc4e41',
      'width': 2.5,
      // Attack-path edges always tell their story
      'text-opacity': 0.9,
    },
  },
  // Hovered or pinned edges thicken slightly and reveal their relationship
  {
    selector: 'edge.edge-hover, edge.label-pinned',
    style: {
      'width': 2.5,
      'text-opacity': 1,
    },
  },
  {
    selector: 'node.focused',
    style: {
      'border-width': 3,
      'border-color': '#dc4e41',
      'border-opacity': 1,
      'text-opacity': 0.95,
    },
  },
  { selector: '.entering', style: { 'opacity': 0 } },
  {
    selector: 'node.hl',
    style: {
      'text-opacity': 0.95,
      'border-opacity': 0.45,
    },
  },
  {
    selector: '.dim',
    style: {
      'opacity': 0.1,
      'text-opacity': 0,
      'text-background-opacity': 0,
    },
  },
  // Persistent twin of the hover highlight: while a node is focused, its
  // closed neighborhood stays lit and the rest recedes, so the connection
  // between the focused node and its inspector panel is always visible.
  {
    selector: 'node.focus-hl',
    style: {
      'text-opacity': 0.95,
      'border-opacity': 0.45,
      'label': 'data(shortLabel)',
    },
  },
  {
    selector: '.focus-dim',
    style: {
      'opacity': 0.14,
      'text-opacity': 0,
      'text-background-opacity': 0,
    },
  },
  { selector: '.ts-hidden', style: { 'display': 'none' } },
  // Incident sections carry no paint of their own: the spatial grid, the
  // floating label, and the focus fog (a DOM overlay) do the separating.
  // Declared last so the section label always wins over zoom-band rules.
  {
    selector: ':parent',
    style: {
      'shape': 'ellipse',
      'background-opacity': 0,
      'border-width': 0,
      'padding': 48,
      'events': 'no',
      'label': 'data(label)',
      'font-size': 13,
      'font-family': '"Oswald", "Arial Narrow", sans-serif',
      'color': '#8a99a8',
      'text-valign': 'top',
      'text-halign': 'center',
      'text-margin-y': -8,
      'text-opacity': 0.85,
      'text-outline-opacity': 0,
    },
  },
  // Nodes reached by more than one incident: they sit between sections and
  // wear a dashed neutral ring marking them as the connection point.
  {
    selector: 'node.shared-node',
    style: {
      'border-style': 'dashed',
      'border-color': '#8a99a8',
      'border-opacity': 0.75,
    },
  },
  // The bridge between two incidents stays hidden until a node touching it
  // is hovered, keeping the resting map quiet.
  { selector: '.bridge-hidden', style: { 'display': 'none' } },
  // Selected attack phase: members wear the phase color (set as data when the
  // phase is applied), everything else recedes without leaving the layout.
  {
    selector: 'node.phase-member',
    style: {
      'border-width': 3,
      'border-color': 'data(phaseColor)',
      'border-opacity': 0.95,
      'text-opacity': 0.95,
      'label': 'data(shortLabel)',
    },
  },
  {
    selector: 'edge.phase-member',
    style: {
      'line-color': 'data(phaseColor)',
      'target-arrow-color': 'data(phaseColor)',
      'opacity': 1,
    },
  },
  {
    selector: '.phase-dim',
    style: {
      'opacity': 0.12,
      'text-opacity': 0,
      'text-background-opacity': 0,
    },
  },
] as cytoscape.StylesheetJson

// Edges that bridge two incident sections stay long so the simulation does
// not drag the sections into each other.
const CROSS_SECTION_EDGE_LENGTH = 460

// Continuous force simulation, Obsidian-style: the graph keeps settling,
// new nodes push neighbors aside, dragging a node tugs what it touches.
// Edge length is per-edge so each arrow has room for its label.
const COLA_OPTIONS: ColaLayoutOptions = {
  name: 'cola',
  infinite: true,
  animate: true,
  fit: false,
  centerGraph: false,
  nodeSpacing: 24,
  edgeLength: (edge) =>
    edge.data('crossSection')
      ? CROSS_SECTION_EDGE_LENGTH
      : desiredEdgeLength((edge.data('kind') as string) ?? ''),
  avoidOverlap: true,
  ungrabifyWhileSimulating: false,
  randomize: false,
}

// --- Component ---

// A focus fog circle in rendered (screen) coordinates.
interface SectionGlow {
  id: string
  x: number
  y: number
  d: number
  hover: boolean
}

interface EdgeTooltip {
  kind: string
  confidence: number
  color: string
  x: number
  y: number
}

// One open inspector drawer: which node, where the user has put it, and its
// stacking height. z is a monotonic counter rather than an array position:
// raising a panel must not reorder the DOM, because moving an element
// cancels its pointer capture mid-drag and can swallow an in-flight click.
interface OpenInspector {
  nodeId: string
  x: number
  y: number
  z: number
}

// Positions a NodeInspector absolutely and lets its header drag it around
// the graph canvas. The drag grip is the header only, so chips, relation
// rows, and scrolling inside the body stay ordinary clicks.
function DraggableInspector({
  entry, context, zIndex, focused, container,
  onMove, onSelect, onClose, onNodeFocus, onPhaseSelect, onTechniqueSelect,
}: {
  entry: OpenInspector
  context: NodeContext
  zIndex: number
  focused: boolean
  container: HTMLDivElement | null
  onMove: (x: number, y: number) => void
  onSelect: (e: React.PointerEvent) => void
  onClose: () => void
  onNodeFocus: (nodeId: string) => void
  onPhaseSelect: (phase: AttackPhase) => void
  onTechniqueSelect: (techniqueId: string) => void
}) {
  const dragRef = useRef<{ dx: number; dy: number } | null>(null)
  return (
    <NodeInspector
      context={context}
      focused={focused}
      style={{ left: entry.x, top: entry.y, zIndex }}
      onPanelPointerDown={onSelect}
      headerProps={{
        onPointerDown: (e) => {
          if ((e.target as HTMLElement).closest('.inspector-close')) return
          dragRef.current = { dx: e.clientX - entry.x, dy: e.clientY - entry.y }
          ;(e.currentTarget as HTMLElement).setPointerCapture?.(e.pointerId)
        },
        onPointerMove: (e) => {
          const d = dragRef.current
          if (!d) return
          let x = e.clientX - d.dx
          let y = e.clientY - d.dy
          // Keep at least a grabbable sliver of the panel inside the canvas.
          const rect = container?.getBoundingClientRect()
          if (rect && rect.width > 0) {
            x = Math.min(Math.max(x, 8 - INSPECTOR_WIDTH + 60), rect.width - 60)
            y = Math.min(Math.max(y, 0), rect.height - 36)
          }
          onMove(x, y)
        },
        onPointerUp: () => { dragRef.current = null },
      }}
      onClose={onClose}
      onNodeFocus={onNodeFocus}
      onPhaseSelect={onPhaseSelect}
      onTechniqueSelect={onTechniqueSelect}
    />
  )
}

const INSPECTOR_WIDTH = 270
// Cascade offset for each newly opened drawer so they stack readably.
const INSPECTOR_CASCADE = 26

export function GraphView({
  nodes, edges, chain, timeWindow, focusedNodeId, onNodeFocus,
  incidents, activeIncidentId, onIncidentSelect, phaseFocus,
  getNodeContext, onPhaseSelect, onTechniqueSelect,
}: GraphViewProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const cyRef = useRef<Core | null>(null)
  const layoutRef = useRef<cytoscape.Layouts | null>(null)
  const addedNodeIds = useRef(new Set<string>())
  const addedEdgeIds = useRef(new Set<string>())
  const labelBand = useRef<LabelClass>('labels-faint')
  const firstBatch = useRef(true)
  const [edgeTooltip, setEdgeTooltip] = useState<EdgeTooltip | null>(null)
  const [mini, setMini] = useState<MinimapData | null>(null)
  const [glows, setGlows] = useState<SectionGlow[]>([])
  const assignmentRef = useRef<IncidentAssignment | null>(null)
  const sectionedIds = useRef(new Set<string>())
  const lastMiniAt = useRef(0)
  const hoverSectionRef = useRef<string | null>(null)
  const animatingRef = useRef(false)
  // True while the cursor is scrubbing across the minimap, so the live
  // camera pans it drives are not mistaken for user canvas drags.
  const miniScrubRef = useRef(false)
  const [snapEnabled, setSnapEnabled] = useState(true)
  const snapEnabledRef = useRef(true)
  // Last incident the camera flew to, deduped so repeated renders do not
  // yank the camera away from a user who has panned off to explore.
  const lastFlownRef = useRef<string | null>(null)
  const onNodeFocusRef = useRef(onNodeFocus)
  useEffect(() => { onNodeFocusRef.current = onNodeFocus })
  const focusedNodeIdRef = useRef(focusedNodeId)
  useEffect(() => { focusedNodeIdRef.current = focusedNodeId })
  const onIncidentSelectRef = useRef(onIncidentSelect)
  useEffect(() => { onIncidentSelectRef.current = onIncidentSelect })
  const activeIncidentIdRef = useRef(activeIncidentId)
  useEffect(() => { activeIncidentIdRef.current = activeIncidentId })

  // Snapshot of the map overlays: minimap content (section frames, orphan
  // nodes, related pairs, viewport) plus the focus fog circles for the
  // active and hovered incidents. Reads refs only, so cy event handlers can
  // call it without going stale.
  const recomputeMini = useCallback(() => {
    const cy = cyRef.current
    if (!cy) return
    const parents = cy.nodes(':parent')
    if (parents.length === 0) {
      setMini(null)
      setGlows([])
      return
    }
    lastMiniAt.current = performance.now()
    const sections = parents.map((p) => ({
      id: p.data('incidentId') as string,
      label: p.data('label') as string,
      bb: p.boundingBox({}),
      active: p.data('incidentId') === activeIncidentIdRef.current,
    }))
    const orphanDots = cy
      .nodes(':childless')
      .filter((n) => n.isOrphan() && n.visible())
      .map((n: cytoscape.NodeSingular) => ({ x: n.position('x'), y: n.position('y') }))
    setMini({
      world: cy.elements().boundingBox({}),
      sections,
      orphanDots,
      viewport: cy.extent(),
      related: assignmentRef.current?.relatedPairs ?? [],
    })

    const glowFor = (incidentId: string, hover: boolean): SectionGlow | null => {
      const p = cy.getElementById(`section-${incidentId}`)
      if (p.length === 0) return null
      const bb = p.renderedBoundingBox({})
      return {
        id: incidentId,
        x: (bb.x1 + bb.x2) / 2,
        y: (bb.y1 + bb.y2) / 2,
        d: Math.max(bb.x2 - bb.x1, bb.y2 - bb.y1) * 1.3,
        hover,
      }
    }
    const next: SectionGlow[] = []
    const active = activeIncidentIdRef.current
    if (active) {
      const g = glowFor(active, false)
      if (g) next.push(g)
    }
    const hovered = hoverSectionRef.current
    if (hovered && hovered !== active) {
      const g = glowFor(hovered, true)
      if (g) next.push(g)
    }
    setGlows(next)
  }, [])

  // Auto-snap: once the user stops panning (canvas drag or minimap jump),
  // frame the nearest incident's whole graph. The user's zoom is kept
  // unless the section cannot fit at it, in which case the camera zooms out
  // just enough; it never zooms the user in.
  const snapToNearest = useCallback(() => {
    const cy = cyRef.current
    if (!cy || animatingRef.current || !snapEnabledRef.current) return
    const ext = cy.extent()
    const cx = (ext.x1 + ext.x2) / 2
    const cyy = (ext.y1 + ext.y2) / 2
    let best: cytoscape.NodeSingular | null = null
    let bestD = Infinity
    cy.nodes(':childless').forEach((n) => {
      if (!n.visible()) return
      const p = n.position()
      const d = (p.x - cx) ** 2 + (p.y - cyy) ** 2
      if (d < bestD) {
        bestD = d
        best = n
      }
    })
    if (best === null) return
    const target = best as cytoscape.NodeSingular
    const incident = assignmentRef.current?.primary.get(target.id())
    const parent = incident !== undefined ? cy.getElementById(`section-${incident}`) : null

    if (incident !== undefined && parent !== null && parent.length > 0) {
      const bb = parent.boundingBox({})
      const pad = 70
      const fitZoom = Math.min(
        (cy.width() - pad * 2) / Math.max(bb.x2 - bb.x1, 1),
        (cy.height() - pad * 2) / Math.max(bb.y2 - bb.y1, 1),
      )
      const zoom = Math.max(Math.min(cy.zoom(), fitZoom), 0.2)
      const bx = (bb.x1 + bb.x2) / 2
      const by = (bb.y1 + bb.y2) / 2
      // Already framed: settled, nothing to do. This is also what
      // terminates the snap-then-pan-event cycle.
      const settled = Math.abs(zoom - cy.zoom()) < 1e-3
        && Math.hypot(bx - cx, by - cyy) * cy.zoom() < 14
      if (!settled) {
        animatingRef.current = true
        cy.animate({
          zoom,
          center: { eles: parent },
          duration: 380,
          easing: 'ease-out-cubic',
          complete: () => { animatingRef.current = false },
        })
      }
      if (incident !== activeIncidentIdRef.current) {
        // Arrived by panning; suppress the selection flight.
        lastFlownRef.current = incident
        onIncidentSelectRef.current?.(incident)
      }
      return
    }

    // Unattributed activity: settle on the node itself at the current zoom.
    if (Math.sqrt(bestD) * cy.zoom() > 14) {
      animatingRef.current = true
      cy.animate({
        center: { eles: target },
        duration: 340,
        easing: 'ease-out-cubic',
        complete: () => { animatingRef.current = false },
      })
    }
  }, [])

  // Mount Cytoscape once; tear it down on unmount
  useEffect(() => {
    if (!containerRef.current) return
    const cy = cytoscape({
      container: containerRef.current,
      style: CY_STYLE,
      userZoomingEnabled: true,
      userPanningEnabled: true,
      minZoom: 0.2,
      maxZoom: 2.5,
      boxSelectionEnabled: false,
      autounselectify: true,
    })
    cyRef.current = cy
    labelBand.current = zoomToLabelClass(cy.zoom())
    // Dev-only handle for debugging and UI test drivers.
    if (import.meta.env.DEV) {
      ;(window as unknown as { __cy?: Core }).__cy = cy
    }

    // Tapping an edge pins its relationship: the canvas label stays revealed
    // and a tooltip with the full kind and confidence holds position until
    // the background or a node is tapped.
    let pinnedEdge: cytoscape.EdgeSingular | null = null
    const clearPinnedEdge = () => {
      pinnedEdge?.removeClass('label-pinned')
      pinnedEdge = null
      setEdgeTooltip(null)
    }

    cy.on('tap', 'node', (e) => {
      const target = e.target as cytoscape.NodeSingular
      clearPinnedEdge()
      // Re-tapping the focused node releases it, mirroring a second click on
      // a phase card: logs and timeline drop back to Live.
      if (focusedNodeIdRef.current !== null && focusedNodeIdRef.current === target.id()) {
        onNodeFocusRef.current?.(null)
        return
      }
      // Tapping into another incident's cluster also makes that incident
      // active, so every panel follows the user across the map. The camera
      // stays put; they are already looking at it. Incident first, focus
      // second: the incident switch clears the previous focus, and the new
      // focus must land after it.
      const incident = assignmentRef.current?.primary.get(target.id())
      if (incident !== undefined && incident !== activeIncidentIdRef.current) {
        lastFlownRef.current = incident
        onIncidentSelectRef.current?.(incident)
      }
      onNodeFocusRef.current?.(target.id())
    })
    cy.on('tap', (e) => {
      if (e.target === cy) {
        clearPinnedEdge()
        onNodeFocusRef.current?.(null)
      }
    })

    // Obsidian-style hover: keep the closed neighborhood, fade the rest.
    // Hovering a node beside a hidden inter-incident bridge reveals the
    // whole bridge path while the pointer stays, and hovering any node
    // lights its incident's focus fog.
    let revealedBridge: cytoscape.CollectionReturnValue | null = null
    cy.on('mouseover', 'node', (e) => {
      const target = e.target as cytoscape.NodeSingular
      if (target.isParent()) return
      const hood = target.closedNeighborhood()
      const bridgeNodes = target.neighborhood('node.bridge')
      const bridgeEdges = target.connectedEdges('.bridge')
      let keep = hood
      if (bridgeNodes.length > 0 || bridgeEdges.length > 0) {
        revealedBridge = bridgeNodes
          .union(bridgeEdges)
          .union(bridgeNodes.connectedEdges())
          .union(bridgeNodes.neighborhood())
          .union(bridgeEdges.connectedNodes())
        revealedBridge.removeClass('bridge-hidden')
        keep = keep.union(revealedBridge)
      }
      cy.batch(() => {
        cy.elements().difference(keep).not(':parent').addClass('dim')
        keep.addClass('hl')
      })
      hoverSectionRef.current = assignmentRef.current?.primary.get(target.id()) ?? null
      recomputeMini()
    })
    cy.on('mouseout', 'node', () => {
      cy.batch(() => {
        const els = cy.elements()
        els.removeClass('dim')
        els.removeClass('hl')
        if (revealedBridge) {
          revealedBridge.filter('.bridge').addClass('bridge-hidden')
          revealedBridge = null
        }
      })
      hoverSectionRef.current = null
      recomputeMini()
    })

    // Edge hover reveals the relationship label on the canvas itself (no
    // cursor-chasing tooltip): the edge thickens and its plated label fades
    // in. The pointer cursor signals that a click pins the full detail.
    cy.on('mouseover', 'edge', (e) => {
      if (containerRef.current) containerRef.current.style.cursor = 'pointer'
      ;(e.target as cytoscape.EdgeSingular).addClass('edge-hover')
    })
    cy.on('mouseout', 'edge', (e) => {
      if (containerRef.current) containerRef.current.style.cursor = ''
      ;(e.target as cytoscape.EdgeSingular).removeClass('edge-hover')
    })
    cy.on('tap', 'edge', (e) => {
      const edge = e.target as cytoscape.EdgeSingular
      const conf = (edge.data('confidence') as number) ?? 0.5
      clearPinnedEdge()
      pinnedEdge = edge
      edge.addClass('label-pinned')
      setEdgeTooltip({
        kind: (edge.data('kind') as string).replace(/_/g, ' '),
        confidence: conf,
        color: scoreToColor(conf),
        x: e.renderedPosition.x,
        y: e.renderedPosition.y,
      })
    })

    // Zoom-dependent labels, throttled to one class swap per frame
    let rafId = 0
    cy.on('zoom', () => {
      cancelAnimationFrame(rafId)
      rafId = requestAnimationFrame(() => {
        const band = zoomToLabelClass(cy.zoom())
        if (band === labelBand.current) return
        const prev = labelBand.current
        labelBand.current = band
        cy.batch(() => {
          const els = cy.elements()
          els.removeClass(prev)
          els.addClass(band)
        })
      })
    })

    // Keep the minimap in step with the camera (every pan/zoom frame) and
    // with the continuous simulation (time-throttled on render frames).
    let miniRaf = 0
    cy.on('viewport', () => {
      cancelAnimationFrame(miniRaf)
      miniRaf = requestAnimationFrame(recomputeMini)
    })
    cy.on('render', () => {
      if (performance.now() - lastMiniAt.current > 200) recomputeMini()
    })

    // Idle-pan detection drives the auto-snap; programmatic camera moves
    // are excluded via the animating flag.
    let panTimer: ReturnType<typeof setTimeout> | undefined
    cy.on('pan', () => {
      if (animatingRef.current) return
      clearTimeout(panTimer)
      panTimer = setTimeout(snapToNearest, 380)
    })

    return () => {
      cancelAnimationFrame(rafId)
      cancelAnimationFrame(miniRaf)
      clearTimeout(panTimer)
      layoutRef.current?.stop()
      layoutRef.current = null
      cy.destroy()
      cyRef.current = null
      addedNodeIds.current.clear()
      addedEdgeIds.current.clear()
      sectionedIds.current.clear()
      firstBatch.current = true
    }
  }, [recomputeMini, snapToNearest])

  // Add new nodes and edges incrementally, then restart the simulation
  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return

    const newEls: cytoscape.ElementDefinition[] = []
    const seeded = new Map<string, { x: number; y: number }>()
    const priorNodeIds = new Set(addedNodeIds.current)
    const band = labelBand.current

    // Seed each new node at a connected neighbor's position (plus jitter)
    // so it pushes outward organically instead of flying in from afar.
    // Disconnected newcomers (the start of a separate incident) spawn in
    // clear space to the right of the existing graph rather than on top of
    // it, so incident clusters never stack.
    const seedPosition = (id: string): { x: number; y: number } => {
      for (const e of edges) {
        if (e.src !== id && e.dst !== id) continue
        const other = e.src === id ? e.dst : e.src
        if (seeded.has(other)) {
          const p = seeded.get(other)!
          return { x: p.x + jitter(), y: p.y + jitter() }
        }
        if (priorNodeIds.has(other)) {
          const el = cy.getElementById(other)
          if (el.length > 0) {
            const p = el.position()
            return { x: p.x + jitter(), y: p.y + jitter() }
          }
        }
      }
      if (priorNodeIds.size > 0) {
        const bb = cy.elements().boundingBox({})
        return { x: bb.x2 + 280 + jitter(), y: (bb.y1 + bb.y2) / 2 + jitter() }
      }
      return { x: cy.width() / 2 + jitter(), y: cy.height() / 2 + jitter() }
    }

    for (const n of nodes) {
      if (!addedNodeIds.current.has(n.id)) {
        addedNodeIds.current.add(n.id)
        const pos = seedPosition(n.id)
        seeded.set(n.id, pos)
        newEls.push({
          group: 'nodes',
          data: {
            id: n.id,
            label: n.label,
            shortLabel: shortenNodeLabel(n.label),
            abbrev: abbreviateLabel(n.label),
            kind: n.kind,
            attrs: n.attrs,
            degree: 0,
          },
          position: pos,
          classes: `entering ${band}`,
        })
      }
    }

    for (const e of edges) {
      if (!addedEdgeIds.current.has(e.id)) {
        addedEdgeIds.current.add(e.id)
        newEls.push({
          group: 'edges',
          data: {
            id: e.id,
            source: e.src,
            target: e.dst,
            kind: e.kind,
            ts: e.ts,
            confidence: e.confidence,
          },
          classes: `entering ${band}`,
        })
      }
    }

    if (newEls.length === 0) return

    const added = cy.add(newEls)

    // Refresh degree data so dot sizes grow with connections
    const degrees = computeDegrees(edges)
    degrees.forEach((deg, id) => {
      const el = cy.getElementById(id)
      if (el.length > 0) el.data('degree', deg)
    })

    // Drop the entering class on the next frame; the stylesheet
    // transition fades the new elements in.
    requestAnimationFrame(() => added.removeClass('entering'))

    // Frame the graph without over-zooming: fit on the first batch, and
    // refit later only when a new node lands outside the viewport. fit()
    // on a tiny early graph would otherwise zoom in absurdly, so clamp.
    const clampedFit = () => {
      cy.fit(cy.elements(), 60)
      if (cy.zoom() > 1.1) {
        cy.zoom(1.1)
        cy.center(cy.elements())
      }
    }
    if (firstBatch.current) {
      firstBatch.current = false
      clampedFit()
    } else {
      const ext = cy.extent()
      const outside = added.nodes().some((n) => {
        const p = (n as cytoscape.NodeSingular).position()
        return p.x < ext.x1 || p.x > ext.x2 || p.y < ext.y1 || p.y > ext.y2
      })
      if (outside) clampedFit()
    }

    // A cola layout captures its element set at creation, so restart it
    // to include the new elements. Positions carry over and fit is off,
    // making the restart visually seamless.
    layoutRef.current?.stop()
    layoutRef.current = cy.layout(COLA_OPTIONS as unknown as cytoscape.LayoutOptions)
    layoutRef.current.run()
  }, [nodes, edges])

  // Camera flight to a section.
  const flyToSection = useCallback((incidentId: string) => {
    const cy = cyRef.current
    if (!cy) return
    const parent = cy.getElementById(`section-${incidentId}`)
    if (parent.length === 0) return
    lastFlownRef.current = incidentId
    cy.stop()
    animatingRef.current = true
    cy.animate({
      fit: { eles: parent, padding: 70 },
      duration: 480,
      easing: 'ease-in-out-cubic',
      complete: () => { animatingRef.current = false },
    })
  }, [])

  // Build and maintain the incident sections: a compound frame per incident,
  // node ownership from BFS over each chain, shared nodes left out between
  // frames, and cross-section edges flagged so the simulation keeps the
  // sections apart. A newly formed section that lands on top of an existing
  // one is translated into free space.
  useEffect(() => {
    const cy = cyRef.current
    if (!cy || !incidents || incidents.length === 0) return

    const assignment = assignIncidents(nodes, edges, incidents)
    assignmentRef.current = assignment

    let changed = false
    cy.batch(() => {
      for (const section of assignment.sections) {
        const parentId = `section-${section.id}`
        if (cy.getElementById(parentId).length === 0) {
          changed = true
          cy.add({
            group: 'nodes',
            data: {
              id: parentId,
              label: section.label.toUpperCase(),
              shortLabel: section.label.toUpperCase(),
              abbrev: section.label.toUpperCase(),
              incidentId: section.id,
            },
          })
        }
      }
      for (const [nodeId, owners] of assignment.reachedBy) {
        const el = cy.getElementById(nodeId)
        if (el.length === 0 || el.isParent()) continue
        if (owners.length === 1) {
          const parentId = `section-${owners[0]}`
          el.removeClass('shared-node')
          const current = el.parent()
          if ((current.length === 0 || current.first().id() !== parentId)
              && cy.getElementById(parentId).length > 0) {
            changed = true
            el.move({ parent: parentId })
          }
        } else {
          // Shared nodes are the hidden inter-incident bridge: dashed ring
          // when revealed, invisible until a neighbor is hovered.
          if (!el.hasClass('shared-node')) {
            changed = true
            el.addClass('shared-node bridge bridge-hidden')
          }
          if (el.parent().length > 0) {
            changed = true
            el.move({ parent: null })
          }
        }
      }
      for (const e of edges) {
        const el = cy.getElementById(e.id)
        if (el.length === 0) continue
        const a = assignment.primary.get(e.src)
        const b = assignment.primary.get(e.dst)
        const cross = a !== undefined && b !== undefined && a !== b ? 1 : 0
        if (((el.data('crossSection') as number) ?? 0) !== cross) {
          changed = true
          el.data('crossSection', cross)
        }
        // A direct edge between two sections is itself a hidden bridge.
        if (cross === 1 && !el.hasClass('bridge')) {
          changed = true
          el.addClass('bridge bridge-hidden')
        }
      }
    })

    // The first time a section forms, settle it onto its grid slot so any
    // number of incidents stays organized in reading order.
    for (const section of assignment.sections) {
      if (sectionedIds.current.has(section.id)) continue
      const parent = cy.getElementById(`section-${section.id}`)
      if (parent.length === 0) continue
      sectionedIds.current.add(section.id)
      const slot = sectionSlot(sectionedIds.current.size - 1)
      const bb = parent.boundingBox({})
      const dx = slot.x - (bb.x1 + bb.x2) / 2
      const dy = slot.y - (bb.y1 + bb.y2) / 2
      if (dx !== 0 || dy !== 0) {
        changed = true
        parent.descendants().forEach((n) => {
          const p = n.position()
          n.position({ x: p.x + dx, y: p.y + dy })
        })
      }
    }

    if (changed) {
      layoutRef.current?.stop()
      layoutRef.current = cy.layout(COLA_OPTIONS as unknown as cytoscape.LayoutOptions)
      layoutRef.current.run()
      recomputeMini()
    }
  }, [nodes, edges, incidents, recomputeMini])

  // Selecting an incident flies the camera to its section and refreshes the
  // overlays so its fog lights up.
  useEffect(() => {
    const cy = cyRef.current
    if (!cy || !activeIncidentId) return
    const parent = cy.getElementById(`section-${activeIncidentId}`)
    if (parent.length === 0) return
    if (lastFlownRef.current !== activeIncidentId) flyToSection(activeIncidentId)
    recomputeMini()
  }, [activeIncidentId, incidents, flyToSection, recomputeMini])

  // Update edge confidence data when scores change (score_update);
  // the stylesheet's color function repaints automatically.
  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return

    for (const e of edges) {
      if (!addedEdgeIds.current.has(e.id)) continue
      const el = cy.getElementById(e.id)
      if (el.length === 0) continue
      if ((el.data('confidence') as number) !== e.confidence) {
        el.data('confidence', e.confidence)
      }
    }
  }, [edges])

  // Apply or clear chain highlighting; chain edges also reveal their labels
  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return

    const edgesCol = cy.edges()
    edgesCol.removeClass('chain')
    if (!chain) return

    const ts = chainTimestamps(chain)
    edgesCol.forEach((e) => {
      if (ts.has(e.data('ts') as number)) e.addClass('chain')
    })
  }, [chain])

  // Mirror the focused node into a selection ring
  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return
    cy.nodes().removeClass('focused')
    if (focusedNodeId) {
      const el = cy.getElementById(focusedNodeId)
      if (el.length > 0) el.addClass('focused')
    }
  }, [focusedNodeId, nodes])

  // While a node is focused, hold the hover-style neighborhood highlight:
  // its connections stay lit and everything else fades, tying the graph to
  // the focused inspector panel. Re-applied as the graph streams so new
  // elements pick the right side of the fade.
  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return
    cy.batch(() => {
      cy.elements().removeClass('focus-hl focus-dim')
    })
    if (!focusedNodeId) return
    const target = cy.getElementById(focusedNodeId)
    if (target.length === 0 || target.isParent()) return
    const keep = target.closedNeighborhood()
    cy.batch(() => {
      cy.elements().difference(keep).not(':parent').addClass('focus-dim')
      keep.addClass('focus-hl')
    })
  }, [focusedNodeId, nodes, edges])

  // Open inspector drawers, kept per incident: focusing a node opens its
  // inspector (cascaded so panels stack readably); the user drags them
  // anywhere and pins as many as they like. Switching incidents hides the
  // set without losing it, so returning to an incident restores its panels
  // exactly where they were. Pixel positions are view furniture, so they
  // live here rather than in app state.
  const [inspectorsByIncident, setInspectorsByIncident] = useState<Record<string, OpenInspector[]>>({})
  const inspectorZRef = useRef(60)
  const incidentKey = activeIncidentId ?? 'none'
  const inspectors = inspectorsByIncident[incidentKey] ?? []

  const updateInspectors = useCallback((key: string, updater: (cur: OpenInspector[]) => OpenInspector[]) => {
    setInspectorsByIncident((all) => ({ ...all, [key]: updater(all[key] ?? []) }))
  }, [])

  useEffect(() => {
    if (!focusedNodeId) return
    // A freshly arriving incident auto-activates without clearing the
    // analyst's focus; their focused node must not leak a panel into the
    // new incident's set. Only file a panel under the incident that owns
    // the node (unassigned nodes go to the current bucket).
    const owner = assignmentRef.current?.primary.get(focusedNodeId)
    if (owner !== undefined && activeIncidentId && owner !== activeIncidentId) return
    updateInspectors(incidentKey, (cur) => {
      if (cur.some((i) => i.nodeId === focusedNodeId)) return cur
      const rect = containerRef.current?.getBoundingClientRect()
      const baseX = rect && rect.width > 0 ? Math.max(12, rect.width - INSPECTOR_WIDTH - 64) : 12
      const offset = (cur.length % 6) * INSPECTOR_CASCADE
      inspectorZRef.current += 1
      return [...cur, {
        nodeId: focusedNodeId,
        x: Math.max(12, baseX - offset),
        y: 12 + offset,
        z: inspectorZRef.current,
      }]
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focusedNodeId, incidentKey, activeIncidentId, updateInspectors])

  function moveInspector(nodeId: string, x: number, y: number) {
    updateInspectors(incidentKey, (cur) => cur.map((i) => (i.nodeId === nodeId ? { ...i, x, y } : i)))
  }

  // Pressing a panel raises it by bumping its z; the array (and therefore
  // the DOM) keeps insertion order.
  function raiseInspector(nodeId: string) {
    updateInspectors(incidentKey, (cur) => {
      const entry = cur.find((i) => i.nodeId === nodeId)
      if (!entry || entry.z === inspectorZRef.current) return cur
      inspectorZRef.current += 1
      const z = inspectorZRef.current
      return cur.map((i) => (i.nodeId === nodeId ? { ...i, z } : i))
    })
  }

  function closeInspector(nodeId: string) {
    updateInspectors(incidentKey, (cur) => cur.filter((i) => i.nodeId !== nodeId))
    if (nodeId === focusedNodeId) onNodeFocus?.(null)
  }

  // Pressing a panel (anywhere except its buttons) hands the workspace focus
  // to its node, so the panel, the red ring, and the Logs tab line up.
  function selectInspector(nodeId: string, e: React.PointerEvent) {
    raiseInspector(nodeId)
    if ((e.target as HTMLElement).closest('button')) return
    if (nodeId !== focusedNodeId) onNodeFocus?.(nodeId)
  }

  // Selected attack phase: paint members in the phase color, fade the rest,
  // and frame the phase subgraph. The flown ref dedupes the camera move so
  // streaming graph updates re-apply classes without re-yanking the view.
  const flownPhaseRef = useRef<string | null>(null)
  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return

    cy.batch(() => {
      cy.elements().removeClass('phase-member phase-dim')
    })
    if (!phaseFocus) {
      // Deselecting a focus hands the camera back to the focused incident's
      // framing, exactly like the fit-focused control, so the click-out
      // always lands somewhere deliberate rather than mid-zoom.
      if (flownPhaseRef.current !== null) {
        flownPhaseRef.current = null
        const incidentId = activeIncidentIdRef.current
        if (incidentId) flyToSection(incidentId)
      }
      return
    }

    const members = cy.collection()
    for (const id of [...phaseFocus.nodeIds, ...phaseFocus.edgeIds]) {
      members.merge(cy.getElementById(id))
    }
    cy.batch(() => {
      members.forEach((el) => { el.data('phaseColor', phaseFocus.color) })
      members.addClass('phase-member')
      cy.elements().not(members).not(':parent').addClass('phase-dim')
    })

    const memberNodes = members.nodes()
    if (memberNodes.length > 0 && flownPhaseRef.current !== phaseFocus.id) {
      flownPhaseRef.current = phaseFocus.id
      cy.stop()
      animatingRef.current = true
      cy.animate({
        fit: { eles: memberNodes, padding: 90 },
        duration: 450,
        easing: 'ease-in-out-cubic',
        complete: () => { animatingRef.current = false },
      })
    }
  }, [phaseFocus, flyToSection])

  // Show/hide edges based on time window. Hidden edges stay in the
  // simulation on purpose so node positions hold still while scrubbing.
  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return

    const edgesCol = cy.edges()
    if (!timeWindow) {
      edgesCol.removeClass('ts-hidden')
      return
    }

    const [min, max] = timeWindow
    edgesCol.forEach((e) => {
      const ts = e.data('ts') as number
      if (ts >= min && ts <= max) e.removeClass('ts-hidden')
      else e.addClass('ts-hidden')
    })
  }, [timeWindow])

  // Deliberate camera commands (buttons) must not hand the view straight
  // back to the auto-snap: the flag swallows the pan events they emit.
  function suppressSnapDuring(fn: () => void) {
    animatingRef.current = true
    fn()
    window.setTimeout(() => { animatingRef.current = false }, 60)
  }

  function toggleSnap() {
    setSnapEnabled((on) => {
      snapEnabledRef.current = !on
      return !on
    })
  }

  function zoomBy(factor: number) {
    const cy = cyRef.current
    if (!cy) return
    suppressSnapDuring(() => {
      cy.zoom({ level: cy.zoom() * factor, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } })
    })
  }

  function fitAll() {
    const cy = cyRef.current
    if (!cy) return
    suppressSnapDuring(() => {
      cy.fit(cy.elements(), 30)
      if (cy.zoom() > 1.5) { cy.zoom(1.5); cy.center(cy.elements()) }
    })
  }

  // Frames only the focused incident's graph, the counterpart to fitAll.
  function fitFocused() {
    const id = activeIncidentIdRef.current
    if (id) flyToSection(id)
  }

  function rotateGraph() {
    const cy = cyRef.current
    if (!cy) return
    suppressSnapDuring(() => rotateGraphNow(cy))
  }

  function rotateGraphNow(cy: Core) {
    // Rotate all node positions 90° clockwise around the graph centroid.
    // Distances between nodes are preserved so cola never tangles after rotation.
    const bb = cy.elements().boundingBox({})
    const cx = (bb.x1 + bb.x2) / 2
    const cy_ = (bb.y1 + bb.y2) / 2
    cy.batch(() => {
      cy.nodes(':childless').forEach(node => {
        const { x, y } = node.position()
        const dx = x - cx
        const dy = y - cy_
        // 90° CW in screen coords (Y-down): x' = -dy, y' = dx
        node.position({ x: cx - dy, y: cy_ + dx })
      })
    })
    cy.fit(cy.elements(), 30)
    if (cy.zoom() > 1.5) { cy.zoom(1.5); cy.center(cy.elements()) }
    layoutRef.current?.stop()
    layoutRef.current = cy.layout(COLA_OPTIONS as unknown as cytoscape.LayoutOptions)
    layoutRef.current.run()
  }

  // Minimap navigation: clicking open map pans the camera to that world
  // point at the current zoom.
  function handleMiniJump(x: number, y: number) {
    const cy = cyRef.current
    if (!cy) return
    const zoom = cy.zoom()
    cy.stop()
    animatingRef.current = true
    cy.animate({
      pan: { x: cy.width() / 2 - x * zoom, y: cy.height() / 2 - y * zoom },
      duration: 300,
      easing: 'ease-in-out-cubic',
      // Landing from a minimap jump settles like a pan: snap to the nearest
      // node and light its incident.
      complete: () => {
        animatingRef.current = false
        snapToNearest()
      },
    })
  }

  // Hover scrubbing: while the cursor moves across the minimap the camera
  // pans instantly to keep the hovered world point centered, at the current
  // zoom. Auto-snap is held off until the cursor leaves, then the view
  // settles exactly like the end of a manual pan.
  function handleMiniHover(x: number, y: number) {
    const cy = cyRef.current
    if (!cy) return
    if (!miniScrubRef.current) {
      miniScrubRef.current = true
      cy.stop()
    }
    animatingRef.current = true
    const zoom = cy.zoom()
    cy.pan({ x: cy.width() / 2 - x * zoom, y: cy.height() / 2 - y * zoom })
  }

  function handleMiniHoverEnd() {
    if (!miniScrubRef.current) return
    miniScrubRef.current = false
    animatingRef.current = false
    snapToNearest()
  }

  function handleMiniSection(incidentId: string) {
    onIncidentSelectRef.current?.(incidentId)
    // Fly even when the incident is already active, so the minimap always
    // doubles as a "take me back to it" control.
    flyToSection(incidentId)
  }

  return (
    <div className="graph-view">
      <div ref={containerRef} className="graph-canvas" />
      {glows.map((g) => (
        <div
          key={`${g.id}${g.hover ? '-hover' : ''}`}
          className={`section-glow${g.hover ? ' section-glow-hover' : ''}`}
          style={{ left: g.x, top: g.y, width: g.d, height: g.d }}
        />
      ))}
      {mini && (
        <Minimap
          data={mini}
          onSectionClick={handleMiniSection}
          onJump={handleMiniJump}
          onHover={handleMiniHover}
          onHoverEnd={handleMiniHoverEnd}
        />
      )}
      <div className="graph-controls">
        <button className="graph-ctrl-btn" title="Zoom in" onClick={() => zoomBy(1.25)}>+</button>
        <button className="graph-ctrl-btn" title="Zoom out" onClick={() => zoomBy(0.8)}>&#8722;</button>
        <div className="graph-ctrl-sep" />
        <button className="graph-ctrl-btn" title="Fit all incidents" aria-label="Fit all incidents" onClick={fitAll}>
          {/* Viewfinder holding several incidents */}
          <svg width="15" height="15" viewBox="0 0 14 14" aria-hidden="true">
            <path
              d="M1 4V1h3M10 1h3v3M13 10v3h-3M4 13H1v-3"
              fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round"
            />
            <circle cx="4.8" cy="6" r="1.3" fill="currentColor" />
            <circle cx="9.2" cy="4.8" r="1.3" fill="currentColor" />
            <circle cx="7.2" cy="9.4" r="1.3" fill="currentColor" />
          </svg>
        </button>
        <button
          className="graph-ctrl-btn"
          title="Fit focused incident"
          aria-label="Fit focused incident"
          onClick={fitFocused}
          disabled={!activeIncidentId}
        >
          {/* Viewfinder holding the one focused (red) incident */}
          <svg width="15" height="15" viewBox="0 0 14 14" aria-hidden="true">
            <path
              d="M1 4V1h3M10 1h3v3M13 10v3h-3M4 13H1v-3"
              fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round"
            />
            <circle cx="7" cy="7" r="2.3" fill="#dc4e41" />
          </svg>
        </button>
        <button className="graph-ctrl-btn" title="Rotate 90°" onClick={rotateGraph}>&#8635;</button>
        <div className="graph-ctrl-sep" />
        <button
          className={`graph-ctrl-btn${snapEnabled ? ' graph-ctrl-btn-on' : ''}`}
          title="Toggle auto snap"
          aria-pressed={snapEnabled}
          onClick={toggleSnap}
          style={{ fontSize: 9, fontWeight: 600, letterSpacing: '0.04em' }}
        >
          SNAP
        </button>
      </div>
      <div className="graph-legend">
        {(Object.entries(KIND_COLORS) as [WsNode['kind'], string][]).map(([kind, color]) => (
          <div key={kind} className="graph-legend-item">
            <span className="graph-legend-dot" style={{ background: color }} />
            {kind}
          </div>
        ))}
      </div>
      {getNodeContext && inspectors.map((entry) => {
        const ctx = getNodeContext(entry.nodeId)
        if (!ctx) return null
        return (
          <DraggableInspector
            key={entry.nodeId}
            entry={entry}
            context={ctx}
            zIndex={entry.z}
            focused={entry.nodeId === focusedNodeId}
            container={containerRef.current}
            onMove={(x, y) => moveInspector(entry.nodeId, x, y)}
            onSelect={(e) => selectInspector(entry.nodeId, e)}
            onClose={() => closeInspector(entry.nodeId)}
            onNodeFocus={(id) => onNodeFocus?.(id)}
            onPhaseSelect={(p) => onPhaseSelect?.(p)}
            onTechniqueSelect={(id) => onTechniqueSelect?.(id)}
          />
        )
      })}
      {edgeTooltip && (
        <div
          className="graph-edge-tooltip"
          style={{
            left: edgeTooltip.x + 14,
            top: edgeTooltip.y - 36,
            borderLeftColor: edgeTooltip.color,
          }}
          role="tooltip"
        >
          <div className="graph-edge-tooltip-kind">{edgeTooltip.kind}</div>
          <div className="graph-edge-tooltip-conf">{Math.round(edgeTooltip.confidence * 100)}% confidence</div>
          <div className="graph-edge-tooltip-hint">click background to dismiss</div>
        </div>
      )}
    </div>
  )
}

function jitter(): number {
  return (Math.random() - 0.5) * 80
}
