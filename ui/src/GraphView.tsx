import { useRef, useEffect, useState } from 'react'
import cytoscape from 'cytoscape'
import cola from 'cytoscape-cola'
import type { Core } from 'cytoscape'
import type { WsNode, WsEdge, ChainResultPayload } from './ws'

cytoscape.use(cola)

export interface GraphViewProps {
  nodes: WsNode[]
  edges: WsEdge[]
  chain: ChainResultPayload | null
  timeWindow?: [number, number] | null
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

// Maps suspicion score 0-1 to a color: muted slate -> amber -> red
export function scoreToColor(score: number): string {
  const s = Math.max(0, Math.min(1, score))
  if (s <= 0.5) return lerpColor('#6e7c8c', '#f8be34', s * 2)
  return lerpColor('#f8be34', '#dc4e41', (s - 0.5) * 2)
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

// Maps node degree (connectedness) to dot diameter, Obsidian-style:
// sqrt growth so hubs stand out without dwarfing the graph.
export function degreeToSize(degree: number): number {
  const d = Math.max(0, degree)
  return Math.min(14 + 5 * Math.sqrt(d), 44)
}

export type LabelClass = 'labels-off' | 'labels-faint' | 'labels-on'

// Maps the current zoom level to a label visibility band.
export function zoomToLabelClass(zoom: number): LabelClass {
  if (zoom < 0.7) return 'labels-off'
  if (zoom < 1.2) return 'labels-faint'
  return 'labels-on'
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

// --- Cytoscape stylesheet ---
// Everything is driven by element data and classes; no per-element style
// bypasses anywhere, or they would override the .dim hover fade.

const CY_STYLE: cytoscape.StylesheetJson = [
  {
    selector: 'node',
    style: {
      'shape': 'ellipse',
      'background-color': (ele: cytoscape.NodeSingular) => kindToColor(ele.data('kind') as WsNode['kind']),
      'width': (ele: cytoscape.NodeSingular) => degreeToSize((ele.data('degree') as number) ?? 0),
      'height': (ele: cytoscape.NodeSingular) => degreeToSize((ele.data('degree') as number) ?? 0),
      'border-width': 0,
      'label': 'data(label)',
      'font-size': 10,
      'color': '#e1e6eb',
      'text-opacity': 0,
      'text-valign': 'bottom',
      'text-halign': 'center',
      'text-margin-y': 5,
      'transition-property': 'opacity, text-opacity',
      'transition-duration': 150,
    },
  },
  {
    selector: 'edge',
    style: {
      'width': 1.5,
      'line-color': (ele: cytoscape.EdgeSingular) => scoreToColor((ele.data('confidence') as number) ?? 0.5),
      'target-arrow-color': (ele: cytoscape.EdgeSingular) => scoreToColor((ele.data('confidence') as number) ?? 0.5),
      'target-arrow-shape': 'triangle',
      'arrow-scale': 0.8,
      'curve-style': 'bezier',
      'label': 'data(kind)',
      'font-size': 9,
      'color': '#8c9bab',
      'text-rotation': 'autorotate',
      'text-opacity': 0,
      'transition-property': 'opacity, text-opacity',
      'transition-duration': 150,
    },
  },
  { selector: '.labels-faint', style: { 'text-opacity': 0.45 } },
  { selector: '.labels-on', style: { 'text-opacity': 1 } },
  {
    selector: 'edge.chain',
    style: {
      'line-color': '#dc4e41',
      'target-arrow-color': '#dc4e41',
      'width': 4,
    },
  },
  // Added elements start invisible; removing the class fades them in.
  { selector: '.entering', style: { 'opacity': 0 } },
  // Hovered neighborhood always shows its labels.
  { selector: 'node.hl', style: { 'text-opacity': 1 } },
  // Hover fade for everything outside the neighborhood. Last so it wins.
  { selector: '.dim', style: { 'opacity': 0.12, 'text-opacity': 0 } },
  { selector: '.ts-hidden', style: { 'display': 'none' } },
]

// Continuous force simulation, Obsidian-style: the graph keeps settling,
// new nodes push neighbors aside, dragging a node tugs what it touches.
const COLA_OPTIONS: ColaLayoutOptions = {
  name: 'cola',
  infinite: true,
  animate: true,
  fit: false,
  centerGraph: false,
  nodeSpacing: 24,
  edgeLength: 110,
  avoidOverlap: true,
  ungrabifyWhileSimulating: false,
  randomize: false,
}

// --- Component ---

interface Tooltip {
  node: WsNode
  x: number
  y: number
}

export function GraphView({ nodes, edges, chain, timeWindow }: GraphViewProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const cyRef = useRef<Core | null>(null)
  const layoutRef = useRef<cytoscape.Layouts | null>(null)
  const addedNodeIds = useRef(new Set<string>())
  const addedEdgeIds = useRef(new Set<string>())
  const labelBand = useRef<LabelClass>('labels-faint')
  const firstBatch = useRef(true)
  const [tooltip, setTooltip] = useState<Tooltip | null>(null)

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
    })
    cyRef.current = cy
    labelBand.current = zoomToLabelClass(cy.zoom())

    cy.on('tap', 'node', (e) => {
      const pos = e.renderedPosition
      setTooltip({ node: e.target.data() as WsNode, x: pos.x, y: pos.y })
    })
    cy.on('tap', (e) => {
      if (e.target === cy) setTooltip(null)
    })

    // Obsidian-style hover: keep the closed neighborhood, fade the rest
    cy.on('mouseover', 'node', (e) => {
      const hood = (e.target as cytoscape.NodeSingular).closedNeighborhood()
      cy.batch(() => {
        cy.elements().difference(hood).addClass('dim')
        hood.addClass('hl')
      })
    })
    cy.on('mouseout', 'node', () => {
      cy.batch(() => {
        const els = cy.elements()
        els.removeClass('dim')
        els.removeClass('hl')
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

    return () => {
      cancelAnimationFrame(rafId)
      layoutRef.current?.stop()
      layoutRef.current = null
      cy.destroy()
      cyRef.current = null
      addedNodeIds.current.clear()
      addedEdgeIds.current.clear()
      firstBatch.current = true
    }
  }, [])

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
      return { x: cy.width() / 2 + jitter(), y: cy.height() / 2 + jitter() }
    }

    for (const n of nodes) {
      if (!addedNodeIds.current.has(n.id)) {
        addedNodeIds.current.add(n.id)
        const pos = seedPosition(n.id)
        seeded.set(n.id, pos)
        newEls.push({
          group: 'nodes',
          data: { id: n.id, label: n.label, kind: n.kind, attrs: n.attrs, degree: 0 },
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

  // Apply or clear chain highlighting
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

  return (
    <div className="graph-view">
      <div ref={containerRef} className="graph-canvas" />
      <div className="graph-legend">
        {(Object.entries(KIND_COLORS) as [WsNode['kind'], string][]).map(([kind, color]) => (
          <div key={kind} className="graph-legend-item">
            <span className="graph-legend-dot" style={{ background: color }} />
            {kind}
          </div>
        ))}
      </div>
      {tooltip && (
        <div
          className="graph-tooltip"
          style={{ left: tooltip.x + 12, top: tooltip.y - 10 }}
          role="tooltip"
        >
          <div className="graph-tooltip-label">{tooltip.node.label}</div>
          <div className="graph-tooltip-kind">{tooltip.node.kind}</div>
          {Object.entries(tooltip.node.attrs).map(([k, v]) => (
            <div key={k} className="graph-tooltip-attr">
              <span className="graph-tooltip-key">{k}:</span> {String(v)}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function jitter(): number {
  return (Math.random() - 0.5) * 80
}
