import { describe, it, expect, vi } from 'vitest'
import { render, fireEvent } from '@testing-library/react'
import { Minimap } from '../Minimap'
import type { MinimapData } from '../Minimap'
import { minimapTransform, fromMini } from '../incidentMap'

// Must match the constants in Minimap.tsx.
const MINIMAP_W = 192
const MINIMAP_H = 128
const MINIMAP_PAD = 12

const data: MinimapData = {
  world: { x1: 0, y1: 0, x2: 2000, y2: 1000 },
  sections: [],
  orphanDots: [],
  viewport: { x1: 100, y1: 100, x2: 500, y2: 400 },
  related: [],
}

describe('Minimap hover panning', () => {
  it('reports the hovered world point on mouse move', () => {
    const onHover = vi.fn()
    const { container } = render(
      <Minimap data={data} onSectionClick={() => {}} onJump={() => {}} onHover={onHover} onHoverEnd={() => {}} />
    )
    const svg = container.querySelector('svg')!
    // jsdom reports the svg at (0, 0), so client coords are mini coords.
    fireEvent.mouseMove(svg, { clientX: 96, clientY: 64 })

    const t = minimapTransform(data.world, MINIMAP_W, MINIMAP_H, MINIMAP_PAD)
    const expected = fromMini(t, 96, 64)
    expect(onHover).toHaveBeenCalledTimes(1)
    const [x, y] = onHover.mock.calls[0]
    expect(x).toBeCloseTo(expected.x)
    expect(y).toBeCloseTo(expected.y)
  })

  it('tracks every move, not just the first', () => {
    const onHover = vi.fn()
    const { container } = render(
      <Minimap data={data} onSectionClick={() => {}} onJump={() => {}} onHover={onHover} onHoverEnd={() => {}} />
    )
    const svg = container.querySelector('svg')!
    fireEvent.mouseMove(svg, { clientX: 40, clientY: 40 })
    fireEvent.mouseMove(svg, { clientX: 150, clientY: 90 })
    expect(onHover).toHaveBeenCalledTimes(2)
  })

  it('signals hover end when the mouse leaves', () => {
    const onHoverEnd = vi.fn()
    const { container } = render(
      <Minimap data={data} onSectionClick={() => {}} onJump={() => {}} onHover={() => {}} onHoverEnd={onHoverEnd} />
    )
    const svg = container.querySelector('svg')!
    fireEvent.mouseLeave(svg)
    expect(onHoverEnd).toHaveBeenCalledTimes(1)
  })
})
