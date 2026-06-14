import type { ReactNode } from 'react'
import { CaretDown } from '@phosphor-icons/react'
import type { HandleProps } from './useDashboardLayout'

// A panel's title bar, now a dropdown-style toggle: clicking it collapses the
// panel to a rail. The caret rotates to advertise that the title is clickable,
// so the affordance reads without instructions. The `dash-panel-title` class is
// preserved so the existing per-panel accent bar and live dot still attach.
export function PanelTitle({
  label,
  collapsed,
  onToggle,
  children,
}: {
  label: string
  collapsed: boolean
  onToggle: () => void
  children?: ReactNode
}) {
  return (
    <button
      type="button"
      className="dash-panel-title"
      aria-expanded={!collapsed}
      onClick={onToggle}
      title={collapsed ? `Expand ${label}` : `Collapse ${label}`}
    >
      <span className="dash-panel-caret" aria-hidden="true">
        <CaretDown size={11} weight="bold" />
      </span>
      <span className="dash-panel-title-text">{label}</span>
      {children}
    </button>
  )
}

export type HandleVariant = 'col-left' | 'col-right' | 'row' | 'corner-l' | 'corner-r'

// A drag strip sitting over a gutter (or a square over a corner). The resting
// grip inside is faint; CSS brightens it on hover and the cursor flips to the
// matching resize arrow, so the edge announces it can be dragged. The drag
// behaviour and double-click reset come straight from the layout hook.
export function ResizeHandle({
  variant,
  handle,
  label,
}: {
  variant: HandleVariant
  handle: HandleProps
  label: string
}) {
  // Corners share a `resize-handle-corner` base (sizing, grip, raised z-index)
  // and add a side class for their left/right anchor and diagonal cursor.
  const isCorner = variant === 'corner-l' || variant === 'corner-r'
  const className = isCorner
    ? `resize-handle resize-handle-corner resize-handle-${variant}`
    : `resize-handle resize-handle-${variant}`
  return (
    <div
      role="separator"
      aria-label={label}
      className={className}
      onPointerDown={handle.onPointerDown}
      onDoubleClick={handle.onDoubleClick}
      onPointerEnter={handle.onPointerEnter}
      onPointerMove={handle.onPointerMove}
      onPointerLeave={handle.onPointerLeave}
    >
      <span className="resize-grip" aria-hidden="true" />
    </div>
  )
}
