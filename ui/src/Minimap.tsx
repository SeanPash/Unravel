// Minimap overlay for the incident map: one rounded rect per incident
// section, dashed links between related incidents, faint dots for activity
// outside any section, and the live viewport rectangle. Clicking a section
// selects that incident; clicking open map pans the camera there; holding
// the mouse button and dragging scrubs the camera live across the map.

import { useEffect, useRef } from 'react'
import { minimapTransform, toMini, fromMini } from './incidentMap'
import type { Rect } from './incidentMap'

// Reference size. The host scales the minimap with the graph panel and passes
// the live width/height in; these are the fallback when it does not (and the
// values the unit tests assume).
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
  // Rendered size in px. Omitted in tests, where the reference size applies.
  width?: number
  height?: number
  onSectionClick: (incidentId: string) => void
  onJump: (worldX: number, worldY: number) => void
  // Scrub navigation: fired for every drag move (button held) over the
  // minimap with the world point under the cursor, then once on release.
  onHover: (worldX: number, worldY: number) => void
  onHoverEnd: () => void
  // The incident section under the cursor while scrubbing (null between
  // sections), so the host can preview that incident's overlays.
  onHoverIncident?: (incidentId: string | null) => void
}

const center = (r: Rect) => ({ x: (r.x1 + r.x2) / 2, y: (r.y1 + r.y2) / 2 })

export function Minimap({ data, width = MINIMAP_W, height = MINIMAP_H, onSectionClick, onJump, onHover, onHoverEnd, onHoverIncident }: MinimapProps) {
  // Keep the inner padding proportional to the box so it does not swallow a
  // small minimap or look stranded on a large one.
  const pad = Math.max(6, Math.round(width * (MINIMAP_PAD / MINIMAP_W)))
  const t = minimapTransform(data.world, width, height, pad)
  const sectionById = new Map(data.sections.map((s) => [s.id, s]))

  // Whether the button is held over the minimap, and whether a drag actually
  // moved the camera, so the click that ends a drag doesn't also fire the
  // click-to-jump below.
  const draggingRef = useRef(false)
  const movedRef = useRef(false)
  // A release can land outside the minimap; keep the latest end callback in a
  // ref so the listener registered once still calls the current one.
  const onHoverEndRef = useRef(onHoverEnd)
  onHoverEndRef.current = onHoverEnd

  useEffect(() => {
    const stop = () => {
      if (!draggingRef.current) return
      draggingRef.current = false
      // Settle the view only when the drag actually scrubbed.
      if (movedRef.current) onHoverEndRef.current()
    }
    window.addEventListener('mouseup', stop)
    return () => window.removeEventListener('mouseup', stop)
  }, [])

  const rectOf = (bb: Rect) => {
    const a = toMini(t, bb.x1, bb.y1)
    const b = toMini(t, bb.x2, bb.y2)
    return { x: a.x, y: a.y, width: Math.max(b.x - a.x, 4), height: Math.max(b.y - a.y, 4) }
  }

  const worldPoint = (e: React.MouseEvent<SVGSVGElement>) => {
    const svg = e.currentTarget.getBoundingClientRect()
    return fromMini(t, e.clientX - svg.left, e.clientY - svg.top)
  }

  function handleMouseDown(e: React.MouseEvent<SVGSVGElement>) {
    e.preventDefault()
    draggingRef.current = true
    movedRef.current = false
  }

  // A plain click (no drag) jumps the camera; the click that ends a drag is
  // swallowed so it doesn't fight the snap from the released drag.
  function handleBackgroundClick(e: React.MouseEvent<SVGSVGElement>) {
    if (movedRef.current) {
      movedRef.current = false
      return
    }
    const p = worldPoint(e)
    onJump(p.x, p.y)
  }

  // Scrub navigation only while the button is held: each drag move pans the
  // camera to the world point under the cursor and previews its incident.
  function handleMouseMove(e: React.MouseEvent<SVGSVGElement>) {
    if (!draggingRef.current) return
    movedRef.current = true
    const p = worldPoint(e)
    onHover(p.x, p.y)
    if (onHoverIncident) {
      const section = data.sections.find(
        (s) => p.x >= s.bb.x1 && p.x <= s.bb.x2 && p.y >= s.bb.y1 && p.y <= s.bb.y2,
      )
      onHoverIncident(section?.id ?? null)
    }
  }

  const viewport = rectOf(data.viewport)

  // Outside-viewport scrim: one evenodd path covering the map with the
  // camera's window cut out, so "where you are" reads as a bright opening
  // in a dim field, the way every canvas minimap signals it.
  const vx = Math.max(0, Math.min(viewport.x, width))
  const vy = Math.max(0, Math.min(viewport.y, height))
  const vx2 = Math.max(0, Math.min(viewport.x + viewport.width, width))
  const vy2 = Math.max(0, Math.min(viewport.y + viewport.height, height))
  const scrimPath =
    `M0 0H${width}V${height}H0Z ` +
    `M${vx} ${vy}H${vx2}V${vy2}H${vx}Z`

  return (
    <div className="graph-minimap" role="navigation" aria-label="Incident map">
      <div className="minimap-titlebar">
        <svg width="9" height="9" viewBox="0 0 9 9" aria-hidden="true" className="minimap-crosshair">
          <line x1="4.5" y1="0.5" x2="4.5" y2="8.5" />
          <line x1="0.5" y1="4.5" x2="8.5" y2="4.5" />
          <circle cx="4.5" cy="4.5" r="2.4" />
        </svg>
        <span>MAP</span>
      </div>
      <svg
        className="minimap-canvas"
        width={width}
        height={height}
        viewBox={`0 0 ${width} ${height}`}
        onMouseDown={handleMouseDown}
        onClick={handleBackgroundClick}
        onMouseMove={handleMouseMove}
      >
        <defs>
          <pattern id="minimap-grid" width="12" height="12" patternUnits="userSpaceOnUse">
            <circle cx="1" cy="1" r="0.5" className="minimap-grid-dot" />
          </pattern>
        </defs>
        <rect className="minimap-terrain" width={width} height={height} fill="url(#minimap-grid)" />
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
      </svg>
    </div>
  )
}
