import { vi, describe, it, expect, beforeEach } from 'vitest'
import { render } from '@testing-library/react'
import cytoscape from 'cytoscape'
import {
  scoreToColor,
  kindToColor,
  degreeToSize,
  zoomToLabelClass,
  computeDegrees,
  chainTimestamps,
  KIND_COLORS,
  GraphView,
} from '../GraphView'
import type { ChainResultPayload, WsEdge, WsNode } from '../ws'

// Cytoscape requires a real canvas context that jsdom does not provide.
// Mock the entire module so the component mounts without errors. The
// default export carries a `use` property because GraphView registers
// the cola extension at module scope.
vi.mock('cytoscape', () => {
  const makeCollection = () => ({
    forEach: vi.fn(),
    animate: vi.fn(),
    addClass: vi.fn(),
    removeClass: vi.fn(),
    style: vi.fn(),
    length: 0,
    data: vi.fn(),
    position: vi.fn(() => ({ x: 0, y: 0 })),
  })

  const mockCy = {
    add: vi.fn(() => makeCollection()),
    getElementById: vi.fn(() => ({ ...makeCollection(), length: 0 })),
    edges: vi.fn(() => makeCollection()),
    nodes: vi.fn(() => makeCollection()),
    elements: vi.fn(() => makeCollection()),
    batch: vi.fn((fn: () => void) => fn()),
    on: vi.fn(),
    destroy: vi.fn(),
    zoom: vi.fn(() => 1),
    fit: vi.fn(),
    width: vi.fn(() => 800),
    height: vi.fn(() => 600),
    layout: vi.fn(() => ({ run: vi.fn(), stop: vi.fn() })),
  }

  const factory = Object.assign(
    vi.fn(() => mockCy),
    { use: vi.fn() },
  )
  return { default: factory }
})

vi.mock('cytoscape-cola', () => ({ default: vi.fn() }))

// ---- scoreToColor ----

describe('scoreToColor', () => {
  it('returns the muted slate anchor at score 0', () => {
    // #6e7c8c
    expect(scoreToColor(0)).toBe('rgb(110, 124, 140)')
  })

  it('returns the Splunk amber anchor at score 1, reserving red for the chain', () => {
    // #f8be34
    expect(scoreToColor(1)).toBe('rgb(248, 190, 52)')
  })

  it('blends between the anchors at score 0.5', () => {
    expect(scoreToColor(0.5)).toBe('rgb(179, 157, 96)')
  })

  it('clamps values below 0 to the low anchor', () => {
    expect(scoreToColor(-1)).toBe(scoreToColor(0))
  })

  it('clamps values above 1 to the high anchor', () => {
    expect(scoreToColor(2)).toBe(scoreToColor(1))
  })
})

// ---- kindToColor ----

describe('kindToColor', () => {
  it('maps every kind to its KIND_COLORS entry', () => {
    expect(kindToColor('Process')).toBe(KIND_COLORS.Process)
    expect(kindToColor('Host')).toBe(KIND_COLORS.Host)
    expect(kindToColor('User')).toBe(KIND_COLORS.User)
    expect(kindToColor('NetFlow')).toBe(KIND_COLORS.NetFlow)
  })

  it('assigns four distinct colors', () => {
    const colors = new Set(Object.values(KIND_COLORS))
    expect(colors.size).toBe(4)
  })

  it('falls back to a muted color for unknown kinds', () => {
    const color = kindToColor('Mystery' as WsNode['kind'])
    expect(color).toBeTruthy()
    expect(Object.values(KIND_COLORS)).not.toContain(color)
  })
})

// ---- degreeToSize ----

describe('degreeToSize', () => {
  it('returns the minimum size at degree 0', () => {
    expect(degreeToSize(0)).toBe(16)
  })

  it('strictly increases with degree until the cap', () => {
    expect(degreeToSize(1)).toBeGreaterThan(degreeToSize(0))
    expect(degreeToSize(4)).toBeGreaterThan(degreeToSize(1))
    expect(degreeToSize(9)).toBeGreaterThan(degreeToSize(4))
  })

  it('caps at the maximum size for highly connected nodes', () => {
    expect(degreeToSize(100)).toBe(52)
    expect(degreeToSize(10_000)).toBe(52)
  })

  it('never returns NaN, even for negative input', () => {
    expect(Number.isNaN(degreeToSize(-5))).toBe(false)
    expect(degreeToSize(-5)).toBe(16)
  })
})

// ---- zoomToLabelClass ----

describe('zoomToLabelClass', () => {
  it('hides labels only when zoomed far out', () => {
    expect(zoomToLabelClass(0.3)).toBe('labels-off')
    expect(zoomToLabelClass(0.49)).toBe('labels-off')
  })

  it('shows faint shortened labels at mid zoom', () => {
    expect(zoomToLabelClass(0.5)).toBe('labels-faint')
    expect(zoomToLabelClass(0.7)).toBe('labels-faint')
    expect(zoomToLabelClass(0.99)).toBe('labels-faint')
  })

  it('shows full labels when zoomed in', () => {
    expect(zoomToLabelClass(1.0)).toBe('labels-on')
    expect(zoomToLabelClass(1.5)).toBe('labels-on')
    expect(zoomToLabelClass(3)).toBe('labels-on')
  })
})

// ---- computeDegrees ----

describe('computeDegrees', () => {
  const edge = (id: string, src: string, dst: string): WsEdge => ({
    id, src, dst, kind: 'spawned', ts: 1, confidence: 0.5,
  })

  it('returns an empty map for no edges', () => {
    expect(computeDegrees([]).size).toBe(0)
  })

  it('counts both endpoints of every edge', () => {
    const degrees = computeDegrees([edge('e1', 'a', 'b'), edge('e2', 'a', 'c')])
    expect(degrees.get('a')).toBe(2)
    expect(degrees.get('b')).toBe(1)
    expect(degrees.get('c')).toBe(1)
  })

  it('counts self-loops once per endpoint role', () => {
    const degrees = computeDegrees([edge('e1', 'a', 'a')])
    expect(degrees.get('a')).toBe(2)
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

  it('renders a legend with one entry per node kind', () => {
    const { container } = render(
      <GraphView nodes={[]} edges={[]} chain={null} />
    )
    const legend = container.querySelector('.graph-legend')
    expect(legend).toBeTruthy()
    expect(legend!.querySelectorAll('.graph-legend-item').length).toBe(4)
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

  it('reports node focus on tap and clears it on background tap', () => {
    const onNodeFocus = vi.fn()
    render(
      <GraphView nodes={[]} edges={[]} chain={null} onNodeFocus={onNodeFocus} />
    )

    const mockCy = (cytoscape as unknown as () => Record<string, ReturnType<typeof vi.fn>>)()
    const calls = mockCy.on.mock.calls
    const nodeTap = calls.find((c: unknown[]) => c[0] === 'tap' && c[1] === 'node')![2]
    const bgTap = calls.find((c: unknown[]) => c[0] === 'tap' && typeof c[1] === 'function')![1]

    const fakeNode = {
      id: () => 'proc-1',
      data: () => ({ id: 'proc-1', kind: 'Process', label: 'cmd.exe', attrs: {} }),
    }
    nodeTap({ target: fakeNode, renderedPosition: { x: 10, y: 10 } })
    expect(onNodeFocus).toHaveBeenCalledWith('proc-1')

    bgTap({ target: mockCy })
    expect(onNodeFocus).toHaveBeenCalledWith(null)
  })
})
