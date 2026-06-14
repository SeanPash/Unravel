import { useCallback, useMemo, useRef, useState } from 'react'
import {
  COL_MIN_PX,
  ROW_MIN_PX,
  DEFAULT_COL_RATIOS,
  DEFAULT_ROW_RATIOS,
  clampPair,
  columnTemplate,
  pairToRatios,
  rowTemplate,
  type CollapseState,
} from './dashboardLayout'

export type PanelKey = keyof CollapseState

// Which gutter a drag is acting on. A corner drives a column gutter and the row
// gutter at once, which is what gives it the window-corner feel.
type DragKind =
  | { type: 'col'; gutter: 0 | 1 }
  | { type: 'row' }
  | { type: 'corner'; gutter: 0 | 1 }

function cursorFor(kind: DragKind): string {
  if (kind.type === 'row') return 'row'
  if (kind.type === 'col') return 'col'
  // The graph's bottom-left corner reads as a NE-SW diagonal; bottom-right as
  // NW-SE, matching the native window-resize cursors.
  return kind.gutter === 0 ? 'nesw' : 'nwse'
}

// Park the reset hint just below-right of the pointer, in viewport coords.
function positionHint(hint: HTMLElement, x: number, y: number): void {
  hint.style.left = `${x}px`
  hint.style.top = `${y}px`
}

export interface HandleProps {
  onPointerDown: (e: React.PointerEvent) => void
  onDoubleClick: () => void
}

/**
 * Owns the resizable / collapsible dashboard layout: the column and row
 * proportions, the per-panel collapse flags, and the pointer drag engine.
 *
 * Sizes reset to the defaults on every load by design (no persistence). During
 * a drag the engine writes `grid-template-*` straight to the grid elements so
 * nothing in the React tree re-renders per frame; the final proportions commit
 * to state once on pointer-up.
 */
export function useDashboardLayout() {
  const [colRatios, setColRatios] = useState<number[]>(() => [...DEFAULT_COL_RATIOS])
  const [rowRatios, setRowRatios] = useState<number[]>(() => [...DEFAULT_ROW_RATIOS])
  const [collapsed, setCollapsed] = useState<CollapseState>({
    incidents: false,
    graph: false,
    narration: false,
    detail: false,
  })

  // app-main (owns the row template), app-main-row (owns the column template),
  // the three column cells and the detail cell (measured at drag start), and
  // the floating "double-click to reset" hint.
  const mainRef = useRef<HTMLElement | null>(null)
  const rowGridRef = useRef<HTMLDivElement | null>(null)
  const cellRefs = useRef<(HTMLDivElement | null)[]>([null, null, null])
  const detailRef = useRef<HTMLDivElement | null>(null)
  const hintRef = useRef<HTMLDivElement | null>(null)

  const registerCell = useCallback(
    (index: number) => (el: HTMLDivElement | null) => {
      cellRefs.current[index] = el
    },
    [],
  )

  const toggleCollapse = useCallback((key: PanelKey) => {
    setCollapsed((prev) => ({ ...prev, [key]: !prev[key] }))
  }, [])

  const beginDrag = useCallback(
    (kind: DragKind, e: React.PointerEvent) => {
      e.preventDefault()
      const startX = e.clientX
      const startY = e.clientY
      const wantsCol = kind.type === 'col' || kind.type === 'corner'
      const wantsRow = kind.type === 'row' || kind.type === 'corner'
      const g = kind.type === 'row' ? 0 : kind.gutter

      const liveCol = [...colRatios]
      const liveRow = [...rowRatios]

      // Snapshot rendered pixel sizes of the pair(s) this drag transfers space
      // between, so the clamp works in real screen units.
      const colStart = wantsCol
        ? {
            a: cellRefs.current[g]?.getBoundingClientRect().width ?? 0,
            b: cellRefs.current[g + 1]?.getBoundingClientRect().width ?? 0,
          }
        : null
      const rowStart = wantsRow
        ? {
            a: rowGridRef.current?.getBoundingClientRect().height ?? 0,
            b: detailRef.current?.getBoundingClientRect().height ?? 0,
          }
        : null

      const cursor = cursorFor(kind)
      document.body.classList.add('dash-resizing', `dash-resizing-${cursor}`)
      const hint = hintRef.current
      if (hint) {
        hint.classList.add('dash-resize-hint-active')
        positionHint(hint, startX, startY)
      }

      const move = (ev: PointerEvent) => {
        if (colStart) {
          const { a, b } = clampPair(
            colStart.a,
            colStart.b,
            ev.clientX - startX,
            COL_MIN_PX[g],
            COL_MIN_PX[g + 1],
          )
          const pair = pairToRatios(colRatios[g], colRatios[g + 1], a, b)
          liveCol[g] = pair[0]
          liveCol[g + 1] = pair[1]
          if (rowGridRef.current) {
            rowGridRef.current.style.gridTemplateColumns = columnTemplate(liveCol, collapsed)
          }
        }
        if (rowStart) {
          const { a, b } = clampPair(
            rowStart.a,
            rowStart.b,
            ev.clientY - startY,
            ROW_MIN_PX[0],
            ROW_MIN_PX[1],
          )
          const pair = pairToRatios(rowRatios[0], rowRatios[1], a, b)
          liveRow[0] = pair[0]
          liveRow[1] = pair[1]
          if (mainRef.current) {
            mainRef.current.style.gridTemplateRows = rowTemplate(liveRow, collapsed.detail)
          }
        }
        if (hint) positionHint(hint, ev.clientX, ev.clientY)
      }

      const up = () => {
        window.removeEventListener('pointermove', move)
        window.removeEventListener('pointerup', up)
        document.body.classList.remove('dash-resizing', `dash-resizing-${cursor}`)
        if (hint) hint.classList.remove('dash-resize-hint-active')
        if (colStart) setColRatios(liveCol)
        if (rowStart) setRowRatios(liveRow)
      }

      window.addEventListener('pointermove', move)
      window.addEventListener('pointerup', up)
    },
    [colRatios, rowRatios, collapsed],
  )

  // A double-click anywhere on a gutter snaps that whole dimension back to the
  // reference proportions, matching the "double-click to reset" hint.
  const resetCols = useCallback(() => setColRatios([...DEFAULT_COL_RATIOS]), [])
  const resetRows = useCallback(() => setRowRatios([...DEFAULT_ROW_RATIOS]), [])

  const colHandle = useCallback(
    (gutter: 0 | 1): HandleProps => ({
      onPointerDown: (e) => beginDrag({ type: 'col', gutter }, e),
      onDoubleClick: resetCols,
    }),
    [beginDrag, resetCols],
  )
  const rowHandle = useCallback(
    (): HandleProps => ({
      onPointerDown: (e) => beginDrag({ type: 'row' }, e),
      onDoubleClick: resetRows,
    }),
    [beginDrag, resetRows],
  )
  const cornerHandle = useCallback(
    (gutter: 0 | 1): HandleProps => ({
      onPointerDown: (e) => beginDrag({ type: 'corner', gutter }, e),
      onDoubleClick: () => {
        resetCols()
        resetRows()
      },
    }),
    [beginDrag, resetCols, resetRows],
  )

  // A gutter only exists between two live panels: if either neighbour is a
  // collapsed rail there is nothing to resize, so that handle is withheld.
  const canResize = useMemo(
    () => ({
      gutter0: !collapsed.incidents && !collapsed.graph,
      gutter1: !collapsed.graph && !collapsed.narration,
      row: !collapsed.detail,
    }),
    [collapsed],
  )

  return {
    // Inline templates for the grid containers.
    colTemplate: columnTemplate(colRatios, collapsed),
    rowTemplateValue: rowTemplate(rowRatios, collapsed.detail),
    // Refs to wire onto the DOM.
    mainRef,
    rowGridRef,
    detailRef,
    hintRef,
    registerCell,
    // Collapse.
    collapsed,
    toggleCollapse,
    // Handle wiring.
    colHandle,
    rowHandle,
    cornerHandle,
    canResize: {
      ...canResize,
      corner0: canResize.gutter0 && canResize.row,
      corner1: canResize.gutter1 && canResize.row,
    },
  }
}
