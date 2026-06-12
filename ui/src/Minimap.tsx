// Minimap overlay for the incident map: one rounded rect per incident
// section, dashed links between related incidents, faint dots for activity
// outside any section, and the live viewport rectangle. Clicking a section
// selects that incident; clicking open map pans the camera there.

import { minimapTransform, toMini, fromMini } from './incidentMap'
import type { Rect } from './incidentMap'

const MINIMAP_W = 192
const MINIMAP_H = 128
const MINIMAP_PAD = 12

export interface MinimapSection {
  id: string
  label: string
  bb: Rect
  active: boolean
}

export interface MinimapData {
  world: Rect
  sections: MinimapSection[]
  // Center points of nodes outside every section (model coordinates).
  orphanDots: { x: number; y: number }[]
  viewport: Rect
  related: [string, string][]
}

export interface MinimapProps {
  data: MinimapData
  onSectionClick: (incidentId: string) => void
  onJump: (worldX: number, worldY: number) => void
  // Scrub navigation: fired for every mouse move over the minimap with the
  // world point under the cursor, then once when the cursor leaves.
  onHover: (worldX: number, worldY: number) => void
  onHoverEnd: () => void
}

const center = (r: Rect) => ({ x: (r.x1 + r.x2) / 2, y: (r.y1 + r.y2) / 2 })

export function Minimap({ data, onSectionClick, onJump, onHover, onHoverEnd }: MinimapProps) {
  const t = minimapTransform(data.world, MINIMAP_W, MINIMAP_H, MINIMAP_PAD)
  const sectionById = new Map(data.sections.map((s) => [s.id, s]))

  const rectOf = (bb: Rect) => {
    const a = toMini(t, bb.x1, bb.y1)
    const b = toMini(t, bb.x2, bb.y2)
    return { x: a.x, y: a.y, width: Math.max(b.x - a.x, 4), height: Math.max(b.y - a.y, 4) }
  }

  const worldPoint = (e: React.MouseEvent<SVGSVGElement>) => {
    const svg = e.currentTarget.getBoundingClientRect()
    return fromMini(t, e.clientX - svg.left, e.clientY - svg.top)
  }

  function handleBackgroundClick(e: React.MouseEvent<SVGSVGElement>) {
    const p = worldPoint(e)
    onJump(p.x, p.y)
  }

  function handleMouseMove(e: React.MouseEvent<SVGSVGElement>) {
    const p = worldPoint(e)
    onHover(p.x, p.y)
  }

  const viewport = rectOf(data.viewport)

  return (
    <div className="graph-minimap" role="navigation" aria-label="Incident map">
      <svg
        width={MINIMAP_W}
        height={MINIMAP_H}
        viewBox={`0 0 ${MINIMAP_W} ${MINIMAP_H}`}
        onClick={handleBackgroundClick}
        onMouseMove={handleMouseMove}
        onMouseLeave={onHoverEnd}
      >
        {data.related.map(([a, b]) => {
          const sa = sectionById.get(a)
          const sb = sectionById.get(b)
          if (!sa || !sb) return null
          const pa = toMini(t, center(sa.bb).x, center(sa.bb).y)
          const pb = toMini(t, center(sb.bb).x, center(sb.bb).y)
          return (
            <line
              key={`${a}-${b}`}
              className="minimap-related"
              x1={pa.x} y1={pa.y} x2={pb.x} y2={pb.y}
            />
          )
        })}
        {data.orphanDots.map((d, i) => {
          const p = toMini(t, d.x, d.y)
          return <circle key={i} className="minimap-dot" cx={p.x} cy={p.y} r={1.5} />
        })}
        {data.sections.map((s) => {
          const r = rectOf(s.bb)
          return (
            <g
              key={s.id}
              className={`minimap-section${s.active ? ' minimap-section-active' : ''}`}
              onClick={(e) => { e.stopPropagation(); onSectionClick(s.id) }}
            >
              <ellipse
                cx={r.x + r.width / 2}
                cy={r.y + r.height / 2}
                rx={r.width / 2}
                ry={r.height / 2}
              />
              <text x={r.x + r.width / 2} y={r.y - 3}>{s.label}</text>
            </g>
          )
        })}
        <rect
          className="minimap-viewport"
          x={viewport.x}
          y={viewport.y}
          width={viewport.width}
          height={viewport.height}
          rx={2}
        />
      </svg>
    </div>
  )
}
