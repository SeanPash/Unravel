// Pure layout math for the resizable / collapsible dashboard grid.
//
// The dashboard is one CSS grid: a top row split into three columns
// (Incidents | Provenance Graph | Attack Phases) and a full-width Detail Tabs
// row beneath it. Resizing moves the shared gutter between two neighbours, so
// every drag is a zero-sum transfer of space within a pair. Collapsing a panel
// drops it out of the fr pool and pins it to a fixed rail.
//
// Everything here is side-effect free so the drag engine and its tests can
// exercise the math without a DOM.

// Default proportions, measured from the reference layout. Columns share the
// top row 8:77:15; the top row and the detail tabs share the height 11:3.
export const DEFAULT_COL_RATIOS: readonly number[] = [8, 77, 15]
export const DEFAULT_ROW_RATIOS: readonly number[] = [11, 3]

// Minimum rendered size (px) each track may shrink to under a drag. The graph
// keeps the largest floor since it carries the canvas; the two rails and the
// detail tabs can go smaller. A drag clamps at these before any panel vanishes.
export const COL_MIN_PX: readonly number[] = [140, 260, 150]
export const ROW_MIN_PX: readonly number[] = [220, 90]

// Width/height a panel collapses to: a thin rail that still shows its title.
export const RAIL_PX = 34

export interface CollapseState {
  incidents: boolean
  graph: boolean
  narration: boolean
  detail: boolean
}

// Move the boundary between two adjacent tracks by `delta` px, clamping so
// neither track drops below its minimum. Total size of the pair is preserved,
// so the gutter never leaves a gap. Returns the two new pixel sizes.
export function clampPair(
  startA: number,
  startB: number,
  delta: number,
  minA: number,
  minB: number,
): { a: number; b: number } {
  const total = startA + startB
  const maxA = total - minB
  let a = startA + delta
  if (a > maxA) a = maxA
  if (a < minA) a = minA
  return { a, b: total - a }
}

// Re-split a pair's combined ratio in proportion to its new pixel sizes. The
// pair's ratio sum is held constant so the other tracks in the row keep their
// share; only the dragged pair's split changes.
export function pairToRatios(
  ratioA: number,
  ratioB: number,
  a: number,
  b: number,
): [number, number] {
  const sum = ratioA + ratioB
  const total = a + b
  if (total <= 0) return [ratioA, ratioB]
  const rA = sum * (a / total)
  return [rA, sum - rA]
}

// Replace tracks `index` and `index + 1` of a ratio list with a freshly split
// pair, leaving every other track untouched. Used by the drag engine to fold a
// pairToRatios result back into the full column or row ratio array.
export function withPair(
  ratios: readonly number[],
  index: number,
  pair: [number, number],
): number[] {
  const next = [...ratios]
  next[index] = pair[0]
  next[index + 1] = pair[1]
  return next
}

function frTrack(ratio: number): string {
  // Trim float noise from drags so the inline style stays readable.
  return `${Number(ratio.toFixed(4))}fr`
}

// grid-template-columns for the top row. A collapsed column becomes a fixed
// rail; the rest keep their fr share and reflow to fill the freed width.
export function columnTemplate(
  ratios: readonly number[],
  collapsed: Pick<CollapseState, 'incidents' | 'graph' | 'narration'>,
  railPx: number = RAIL_PX,
): string {
  return [
    collapsed.incidents ? `${railPx}px` : frTrack(ratios[0]),
    collapsed.graph ? `${railPx}px` : frTrack(ratios[1]),
    collapsed.narration ? `${railPx}px` : frTrack(ratios[2]),
  ].join(' ')
}

// grid-template-rows for the whole dashboard. When the detail tabs collapse,
// the row shrinks to its own header height (`auto`) and the top row takes the
// rest; otherwise the two rows share by ratio.
export function rowTemplate(ratios: readonly number[], detailCollapsed: boolean): string {
  if (detailCollapsed) return '1fr auto'
  return `${frTrack(ratios[0])} ${frTrack(ratios[1])}`
}

// Which grid axes size a given panel. Every top-row panel (incidents, graph,
// narration) is sized by both the column split (its width) and the row split
// (the shared top-row height), so resetting any of them restores both axes.
// The full-width detail row is sized by the row split alone.
export type PanelKey = 'incidents' | 'graph' | 'narration' | 'detail'
export function sectionResetAxes(key: PanelKey): { cols: boolean; rows: boolean } {
  if (key === 'detail') return { cols: false, rows: true }
  return { cols: true, rows: true }
}
