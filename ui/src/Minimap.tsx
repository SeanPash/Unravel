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

  // Outside-viewport scrim: one evenodd path covering the map with the
  // camera's window cut out, so "where you are" reads as a bright opening
  // in a dim field, the way every canvas minimap signals it.
  const vx = Math.max(0, Math.min(viewport.x, MINIMAP_W))
  const vy = Math.max(0, Math.min(viewport.y, MINIMAP_H))
  const vx2 = Math.max(0, Math.min(viewport.x + viewport.width, MINIMAP_W))
  const vy2 = Math.max(0, Math.min(viewport.y + viewport.height, MINIMAP_H))
  const scrimPath =
    `M0 0H${MINIMAP_W}V${MINIMAP_H}H0Z ` +
    `M${vx} ${vy}H${vx2}V${vy2}H${vx}Z`

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
        <defs>
          <pattern id="minimap-grid" width="12" height="12" patternUnits="userSpaceOnUse">
            <circle cx="1" cy="1" r="0.5" className="minimap-grid-dot" />
          </pattern>
        </defs>
        <rect className="minimap-terrain" width={MINIMAP_W} height={MINIMAP_H} fill="url(#minimap-grid)" />
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
        <path className="minimap-scrim" d={scrimPath} fillRule="evenodd" />
        <rect
          className="minimap-viewport"
          x={viewport.x}
          y={viewport.y}
          width={viewport.width}
          height={viewport.height}
          rx={1.5}
        />
        {/* Instrument label: a tiny crosshair tick plus MAP says what this is. */}
        <g className="minimap-maplabel" aria-hidden="true">
          <g className="minimap-crosshair">
            <line x1="8.5" y1="6" x2="8.5" y2="13" />
            <line x1="5" y1="9.5" x2="12" y2="9.5" />
            <circle cx="8.5" cy="9.5" r="2.2" />
          </g>
          <text x="16" y="12.5">MAP</text>
        </g>
      </svg>
    </div>
  )
}
