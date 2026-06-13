// Investigation context for a focused graph node: not what the node is (its
// raw attrs say that) but why it matters. Everything here is derived from
// data the app already holds: relationships from the edges, attack phase and
// technique membership from the chain-derived foci, and the why from the
// chain steps whose evidence touches the node. Pure, React-free, vitest-able.

import type { ChainResultPayload, LogEventPayload, WsEdge, WsNode } from './ws'
import type { AttackPhase, TechniqueFocus } from './attackPhases'
import { summarizeLog } from './logFilter'

export interface NodeRelation {
  node: WsNode
  // Edge relationship as emitted by the engine, e.g. 'spawned'.
  kind: string
  ts: number
  confidence: number
}

// One raw event backing the node's edges: the actual evidence, surfaced in
// the inspector instead of only counted. raw is carried so a row can expand
// in place without a round-trip to the Logs tab.
export interface EvidenceItem {
  eventId: string
  ts: number
  source: string
  summary: string
  raw: Record<string, unknown>
}

export interface NodeContext {
  node: WsNode
  parents: NodeRelation[]
  children: NodeRelation[]
  phases: AttackPhase[]
  techniques: TechniqueFocus[]
  // Chain step descriptions backed by this node's edges: the engine's own
  // words for the node's role in the attack.
  chainDescriptions: string[]
  onAttackPath: boolean
  // Strongest scored edge touching the node.
  maxConfidence: number
  // The actual raw events behind the node's edges, time-sorted. The Logs tab
  // shows these when the node is focused; the inspector lists them inline.
  evidence: EvidenceItem[]
  // Convenience count, == evidence.length.
  evidenceCount: number
}

export function buildNodeContext(
  nodeId: string,
  nodes: Record<string, WsNode>,
  edges: WsEdge[],
  chain: ChainResultPayload | null,
  phases: AttackPhase[],
  techniqueFoci: TechniqueFocus[],
  logs: Record<string, LogEventPayload> = {},
): NodeContext | null {
  const node = nodes[nodeId]
  if (!node) return null

  const parents: NodeRelation[] = []
  const children: NodeRelation[] = []
  const eventIds = new Set<string>()
  let maxConfidence = 0
  for (const e of edges) {
    if (e.src !== nodeId && e.dst !== nodeId) continue
    if (e.source_event_id) eventIds.add(e.source_event_id)
    maxConfidence = Math.max(maxConfidence, e.confidence)
    const otherId = e.src === nodeId ? e.dst : e.src
    const other = nodes[otherId]
    if (!other) continue
    const rel: NodeRelation = { node: other, kind: e.kind, ts: e.ts, confidence: e.confidence }
    if (e.dst === nodeId) parents.push(rel)
    else children.push(rel)
  }
  parents.sort((a, b) => a.ts - b.ts)
  children.sort((a, b) => a.ts - b.ts)

  const chainDescriptions = (chain?.steps ?? [])
    .filter((s) => eventIds.has(s.event_id))
    .sort((a, b) => a.ts - b.ts)
    .map((s) => s.description)

  const evidence: EvidenceItem[] = []
  for (const id of eventIds) {
    const log = logs[id]
    if (!log) continue
    evidence.push({
      eventId: id,
      ts: log.ts,
      source: log.source,
      summary: summarizeLog(log),
      raw: log.raw,
    })
  }
  evidence.sort((a, b) => a.ts - b.ts)

  return {
    node,
    parents,
    children,
    phases: phases.filter((p) => p.nodeIds.includes(nodeId)),
    techniques: techniqueFoci.filter((t) => t.nodeIds.includes(nodeId)),
    chainDescriptions,
    onAttackPath: chainDescriptions.length > 0,
    maxConfidence,
    evidence,
    // The node may touch events the client has not received the log for yet;
    // count the known evidence so the header matches what is listed.
    evidenceCount: evidence.length,
  }
}
