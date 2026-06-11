// Pure logic for the incident map: which incident owns which graph nodes,
// which incidents are related, and the geometry used to keep incident
// sections from overlapping and to draw the minimap. Kept free of React and
// Cytoscape so vitest can exercise every branch directly.

import type { WsNode, WsEdge, ChainResultPayload } from './ws'

export interface IncidentRef {
  id: string
  label: string
  firstSeen: number
  chain: ChainResultPayload | null
}

export interface IncidentSection {
  id: string
  label: string
  // Nodes owned exclusively by this incident. Nodes reached by several
  // incidents are deliberately left out so they sit between sections as
  // visible bridges.
  nodeIds: string[]
}

export interface IncidentAssignment {
  // Every incident that reaches a node, ordered by incident firstSeen.
  reachedBy: Map<string, string[]>
  // First (oldest) incident reaching the node.
  primary: Map<string, string>
  sections: IncidentSection[]
  // Incident id pairs that share a node or are joined by a direct edge,
  // each pair sorted and de-duplicated.
  relatedPairs: [string, string][]
}

// Endpoints of the edges produced by a chain's steps: the structural seed
// of an incident inside the global graph.
export function seedNodeIds(chain: ChainResultPayload, edges: WsEdge[]): Set<string> {
  const eventIds = new Set(chain.steps.map((s) => s.event_id))
  const out = new Set<string>()
  for (const e of edges) {
    if (e.source_event_id !== undefined && eventIds.has(e.source_event_id)) {
      out.add(e.src)
      out.add(e.dst)
    }
  }
  return out
}

// Multi-source BFS from every incident's seed nodes, expanding one wave at a
// time across the whole wave front so two incidents arriving at a node in
// the same wave share it rather than racing for it.
export function assignIncidents(
  nodes: WsNode[],
  edges: WsEdge[],
  incidents: IncidentRef[],
): IncidentAssignment {
  const ordered = [...incidents]
    .filter((i) => i.chain !== null)
    .sort((a, b) => a.firstSeen - b.firstSeen)
  const incidentOrder = new Map(ordered.map((inc, i) => [inc.id, i]))

  const adjacency = new Map<string, string[]>()
  for (const e of edges) {
    if (!adjacency.has(e.src)) adjacency.set(e.src, [])
    if (!adjacency.has(e.dst)) adjacency.set(e.dst, [])
    adjacency.get(e.src)!.push(e.dst)
    adjacency.get(e.dst)!.push(e.src)
  }

  const reachedBy = new Map<string, Set<string>>()
  let frontier: string[] = []
  for (const inc of ordered) {
    for (const nodeId of seedNodeIds(inc.chain!, edges)) {
      if (!reachedBy.has(nodeId)) {
        reachedBy.set(nodeId, new Set())
        frontier.push(nodeId)
      }
      reachedBy.get(nodeId)!.add(inc.id)
    }
  }

  while (frontier.length > 0) {
    // Collect the next wave first, then commit, so same-wave arrivals from
    // different incidents both land.
    const arrivals = new Map<string, Set<string>>()
    for (const nodeId of frontier) {
      const owners = reachedBy.get(nodeId)!
      for (const neighbor of adjacency.get(nodeId) ?? []) {
        if (reachedBy.has(neighbor)) continue
        if (!arrivals.has(neighbor)) arrivals.set(neighbor, new Set())
        for (const inc of owners) arrivals.get(neighbor)!.add(inc)
      }
    }
    frontier = []
    for (const [nodeId, owners] of arrivals) {
      reachedBy.set(nodeId, owners)
      frontier.push(nodeId)
    }
  }

  const sortIncidents = (ids: Iterable<string>) =>
    [...ids].sort((a, b) => (incidentOrder.get(a) ?? 0) - (incidentOrder.get(b) ?? 0))

  const reachedSorted = new Map<string, string[]>()
  const primary = new Map<string, string>()
  for (const [nodeId, owners] of reachedBy) {
    const sorted = sortIncidents(owners)
    reachedSorted.set(nodeId, sorted)
    primary.set(nodeId, sorted[0])
  }

  const nodeIdsPresent = new Set(nodes.map((n) => n.id))
  const sections: IncidentSection[] = []
  for (const inc of ordered) {
    const nodeIds = [...reachedSorted.entries()]
      .filter(([nodeId, owners]) => owners.length === 1 && owners[0] === inc.id && nodeIdsPresent.has(nodeId))
      .map(([nodeId]) => nodeId)
    if (nodeIds.length > 0) sections.push({ id: inc.id, label: inc.label, nodeIds })
  }

  const relatedKeys = new Set<string>()
  const relatedPairs: [string, string][] = []
  const addPair = (a: string, b: string) => {
    if (a === b) return
    const [lo, hi] = sortIncidents([a, b])
    const key = `${lo}|${hi}`
    if (relatedKeys.has(key)) return
    relatedKeys.add(key)
    relatedPairs.push([lo, hi])
  }
  for (const owners of reachedSorted.values()) {
    for (let i = 0; i < owners.length; i++) {
      for (let j = i + 1; j < owners.length; j++) addPair(owners[i], owners[j])
    }
  }
  for (const e of edges) {
    const a = primary.get(e.src)
    const b = primary.get(e.dst)
    if (a !== undefined && b !== undefined) addPair(a, b)
  }

  return { reachedBy: reachedSorted, primary, sections, relatedPairs }
}

// --- Geometry ---

export interface Rect {
  x1: number
  y1: number
  x2: number
  y2: number
}

export function rectsOverlap(a: Rect, b: Rect, pad = 0): boolean {
  return a.x1 - pad < b.x2 && a.x2 + pad > b.x1 && a.y1 - pad < b.y2 && a.y2 + pad > b.y1
}

// Translation that moves `moving` clear of every `fixed` rect: zero when it
// is already clear, otherwise a shift to the right of the rightmost fixed
// rect, vertically aligned with the fixed rects' center band.
export function escapeOverlap(moving: Rect, fixed: Rect[], gap: number): { dx: number; dy: number } {
  if (fixed.length === 0 || !fixed.some((f) => rectsOverlap(moving, f, gap))) {
    return { dx: 0, dy: 0 }
  }
  const maxX = Math.max(...fixed.map((f) => f.x2))
  const centerY = fixed.reduce((acc, f) => acc + (f.y1 + f.y2) / 2, 0) / fixed.length
  return {
    dx: maxX + gap - moving.x1,
    dy: centerY - (moving.y1 + moving.y2) / 2,
  }
}

// --- Minimap projection ---

export interface MiniTransform {
  scale: number
  ox: number
  oy: number
}

// Uniform scale-to-fit of a world rect into a minimap of w x h with padding,
// content centered on both axes.
export function minimapTransform(world: Rect, w: number, h: number, pad: number): MiniTransform {
  const ww = Math.max(world.x2 - world.x1, 1)
  const wh = Math.max(world.y2 - world.y1, 1)
  const scale = Math.min((w - pad * 2) / ww, (h - pad * 2) / wh)
  return {
    scale,
    ox: (w - ww * scale) / 2 - world.x1 * scale,
    oy: (h - wh * scale) / 2 - world.y1 * scale,
  }
}

export function toMini(t: MiniTransform, x: number, y: number): { x: number; y: number } {
  return { x: x * t.scale + t.ox, y: y * t.scale + t.oy }
}

export function fromMini(t: MiniTransform, x: number, y: number): { x: number; y: number } {
  return { x: (x - t.ox) / t.scale, y: (y - t.oy) / t.scale }
}
