import { useRef, useEffect, useState } from 'react'
import cytoscape from 'cytoscape'
import type { Core } from 'cytoscape'
import type { WsNode, WsEdge, ChainResultPayload } from './ws'

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

// Maps suspicion score 0-1 to a color: gray -> orange -> red
export function scoreToColor(score: number): string {
  const s = Math.max(0, Math.min(1, score))
  if (s <= 0.5) return lerpColor('#8b949e', '#d29922', s * 2)
  return lerpColor('#d29922', '#da3633', (s - 0.5) * 2)
}

// Maps node kind to a Cytoscape shape string
export function kindToShape(kind: WsNode['kind']): string {
  switch (kind) {
    case 'Process': return 'ellipse'
    case 'Host': return 'rectangle'
    case 'User': return 'diamond'
    case 'NetFlow': return 'triangle'
    default: return 'ellipse'
  }
}

// Returns the set of edge timestamps that are part of the chain
export function chainTimestamps(chain: ChainResultPayload | null): Set<number> {
  if (!chain) return new Set()
  return new Set(chain.steps.map(s => s.ts))
}

// --- Cytoscape stylesheet ---

const CY_STYLE: cytoscape.StylesheetStyle[] = [
  {
    selector: 'node',
    style: {
      'background-color': '#1f6feb',
      'label': 'data(label)',
      'font-size': 10,
      'color': '#c9d1d9',
      'text-valign': 'bottom',
      'text-halign': 'center',
      'text-margin-y': 4,
      'width': 36,
      'height': 36,
      'border-width': 2,
      'border-color': '#388bfd',
    },
  },
  {
    selector: 'edge',
    style: {
      'width': 2,
      'line-color': '#484f58',
      'target-arrow-color': '#484f58',
      'target-arrow-shape': 'triangle',
      'curve-style': 'bezier',
      'label': 'data(kind)',
      'font-size': 9,
      'color': '#8b949e',
      'text-rotation': 'autorotate',
    },
  },
]

// --- Component ---

interface Tooltip {
  node: WsNode
  x: number
  y: number
}

export function GraphView({ nodes, edges, chain, timeWindow }: GraphViewProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const cyRef = useRef<Core | null>(null)
  const addedNodeIds = useRef(new Set<string>())
  const addedEdgeIds = useRef(new Set<string>())
  const [tooltip, setTooltip] = useState<Tooltip | null>(null)

  // Mount Cytoscape once; tear it down on unmount
  useEffect(() => {
    if (!containerRef.current) return
    const cy = cytoscape({
      container: containerRef.current,
      style: CY_STYLE,
      userZoomingEnabled: true,
      userPanningEnabled: true,
    })
    cyRef.current = cy

    cy.on('tap', 'node', (e) => {
      const pos = e.renderedPosition
      setTooltip({ node: e.target.data() as WsNode, x: pos.x, y: pos.y })
    })
    cy.on('tap', (e) => {
      if (e.target === cy) setTooltip(null)
    })

    return () => {
      cy.destroy()
      cyRef.current = null
      addedNodeIds.current.clear()
      addedEdgeIds.current.clear()
    }
  }, [])

  // Add new nodes and edges incrementally; fade each in over 300ms
  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return

    const newEls: cytoscape.ElementDefinition[] = []
    let hasNewNodes = false

    for (const n of nodes) {
      if (!addedNodeIds.current.has(n.id)) {
        addedNodeIds.current.add(n.id)
        hasNewNodes = true
        newEls.push({
          group: 'nodes',
          data: { id: n.id, label: n.label, kind: n.kind, attrs: n.attrs },
          style: { shape: kindToShape(n.kind), opacity: 0 },
        })
      }
    }

    for (const e of edges) {
      if (!addedEdgeIds.current.has(e.id)) {
        addedEdgeIds.current.add(e.id)
        const color = scoreToColor(e.confidence)
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
          style: { 'line-color': color, 'target-arrow-color': color, opacity: 0 },
        })
      }
    }

    if (newEls.length === 0) return

    const added = cy.add(newEls)

    if (hasNewNodes) {
      cy.layout({ name: 'cose', animate: false }).run()
    }

    added.animate({ style: { opacity: 1 }, duration: 300 })
  }, [nodes, edges])

  // Update edge colors when confidence values change (score_update)
  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return

    for (const e of edges) {
      if (!addedEdgeIds.current.has(e.id)) continue
      const el = cy.getElementById(e.id)
      if (el.length === 0) continue
      const stored = el.data('confidence') as number
      if (stored !== e.confidence) {
        el.data('confidence', e.confidence)
        const color = scoreToColor(e.confidence)
        el.style({ 'line-color': color, 'target-arrow-color': color })
      }
    }
  }, [edges])

  // Apply or clear chain highlighting
  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return

    // Reset all edges to their score-based color
    cy.edges().forEach((e) => {
      const conf = (e.data('confidence') as number) ?? 0.5
      const color = scoreToColor(conf)
      e.style({ 'line-color': color, 'target-arrow-color': color, width: 2 })
    })

    if (!chain) return

    const ts = chainTimestamps(chain)
    cy.edges().forEach((e) => {
      if (ts.has(e.data('ts') as number)) {
        e.style({ 'line-color': '#f85149', 'target-arrow-color': '#f85149', width: 4 })
      }
    })
  }, [chain])

  // Show/hide edges based on time window
  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return

    if (!timeWindow) {
      cy.edges().forEach((e) => {
        e.style('display', 'element')
      })
      return
    }

    const [min, max] = timeWindow
    cy.edges().forEach((e) => {
      const ts = e.data('ts') as number
      e.style('display', ts >= min && ts <= max ? 'element' : 'none')
    })
  }, [timeWindow])

  return (
    <div className="graph-view">
      <div ref={containerRef} className="graph-canvas" />
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
