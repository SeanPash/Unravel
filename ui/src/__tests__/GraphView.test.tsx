import { vi, describe, it, expect, beforeEach } from 'vitest'
import { render } from '@testing-library/react'
import { scoreToColor, kindToShape, chainTimestamps, GraphView } from '../GraphView'
import type { ChainResultPayload } from '../ws'

// Cytoscape requires a real canvas context that jsdom does not provide.
// Mock the entire module so the component mounts without errors.
vi.mock('cytoscape', () => {
  const makeCollection = () => ({
    forEach: vi.fn(),
    animate: vi.fn(),
    style: vi.fn(),
    length: 0,
    data: vi.fn(),
  })

  const mockCy = {
    add: vi.fn(() => makeCollection()),
    getElementById: vi.fn(() => ({ ...makeCollection(), length: 0 })),
    edges: vi.fn(() => makeCollection()),
    on: vi.fn(),
    destroy: vi.fn(),
    layout: vi.fn(() => ({ run: vi.fn() })),
  }

  return { default: vi.fn(() => mockCy) }
})

// ---- scoreToColor ----

describe('scoreToColor', () => {
  it('returns a gray-toned color at score 0', () => {
    const color = scoreToColor(0)
    // gray: rgb(139, 148, 158)
    expect(color).toBe('rgb(139, 148, 158)')
  })

  it('returns an orange-toned color at score 0.5', () => {
    const color = scoreToColor(0.5)
    // orange: rgb(210, 153, 34)
    expect(color).toBe('rgb(210, 153, 34)')
  })

  it('returns a red-toned color at score 1', () => {
    const color = scoreToColor(1)
    // red: rgb(218, 54, 51)
    expect(color).toBe('rgb(218, 54, 51)')
  })

  it('clamps values below 0 to gray', () => {
    expect(scoreToColor(-1)).toBe(scoreToColor(0))
  })

  it('clamps values above 1 to red', () => {
    expect(scoreToColor(2)).toBe(scoreToColor(1))
  })
})

// ---- kindToShape ----

describe('kindToShape', () => {
  it('maps Process to ellipse', () => {
    expect(kindToShape('Process')).toBe('ellipse')
  })

  it('maps Host to rectangle', () => {
    expect(kindToShape('Host')).toBe('rectangle')
  })

  it('maps User to diamond', () => {
    expect(kindToShape('User')).toBe('diamond')
  })

  it('maps NetFlow to triangle', () => {
    expect(kindToShape('NetFlow')).toBe('triangle')
  })
})

// ---- chainTimestamps ----

describe('chainTimestamps', () => {
  it('returns an empty set for null', () => {
    const ts = chainTimestamps(null)
    expect(ts.size).toBe(0)
  })

  it('returns timestamps from chain steps', () => {
    const chain: ChainResultPayload = {
      confidence: 0.91,
      steps: [
        { event_id: 'evt-001', description: 'step 1', confidence: 0.9, ts: 1749100030 },
        { event_id: 'evt-002', description: 'step 2', confidence: 0.85, ts: 1749100060 },
      ],
    }
    const ts = chainTimestamps(chain)
    expect(ts.size).toBe(2)
    expect(ts.has(1749100030)).toBe(true)
    expect(ts.has(1749100060)).toBe(true)
  })

  it('does not include timestamps not in the chain', () => {
    const chain: ChainResultPayload = {
      confidence: 0.9,
      steps: [{ event_id: 'evt-001', description: 'step 1', confidence: 0.9, ts: 100 }],
    }
    const ts = chainTimestamps(chain)
    expect(ts.has(999)).toBe(false)
  })
})

// ---- GraphView component ----

describe('GraphView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders without crashing with empty props', () => {
    const { container } = render(
      <GraphView nodes={[]} edges={[]} chain={null} />
    )
    expect(container.querySelector('.graph-view')).toBeTruthy()
  })

  it('renders without crashing with nodes and edges', () => {
    const nodes = [
      { id: 'proc-1', kind: 'Process' as const, label: 'cmd.exe', attrs: { pid: 1 } },
      { id: 'proc-2', kind: 'Process' as const, label: 'powershell.exe', attrs: { pid: 2 } },
    ]
    const edges = [
      { id: 'edge-1', src: 'proc-1', dst: 'proc-2', kind: 'spawned', ts: 1749100030, confidence: 0.72 },
    ]
    const { container } = render(
      <GraphView nodes={nodes} edges={edges} chain={null} />
    )
    expect(container.querySelector('.graph-view')).toBeTruthy()
  })

  it('renders without crashing when chain is provided', () => {
    const chain: ChainResultPayload = {
      confidence: 0.91,
      steps: [
        { event_id: 'evt-001', description: 'cmd spawned powershell', confidence: 0.9, ts: 1749100030 },
      ],
    }
    const { container } = render(
      <GraphView nodes={[]} edges={[]} chain={chain} />
    )
    expect(container.querySelector('.graph-view')).toBeTruthy()
  })
})
