// Pure derivation of the attack phase cards from a chain extraction. The
// structure of every phase (which steps, nodes, edges, timestamps, and what
// confidence) comes from the engine's chain result; the AI narration only
// contributes the per-phase prose summary. Kept free of React and Cytoscape
// so vitest can exercise every branch directly.

import type { ChainResultPayload, ChainStep, NarrationPayload, WsEdge } from './ws'
import { PHASE_COLORS } from './timeline'

export interface PhaseTechnique {
  id: string
  name: string
}

export interface AttackPhase {
  // Kebab-case tactic name, stable across renders and shared with the
  // engine narrator's phase ids.
  id: string
  title: string
  index: number
  color: string
  summary: string
  // True when the summary came from the AI narration rather than the
  // step-description fallback.
  aiSummary: boolean
  // Mean confidence of the phase's chain steps.
  confidence: number
  eventIds: string[]
  nodeIds: string[]
  edgeIds: string[]
  startTs: number
  endTs: number
  techniques: PhaseTechnique[]
  evidenceCount: number
}

export function phaseSlug(tactic: string): string {
  return tactic.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')
}

const normalizeTitle = (t: string) => t.trim().toLowerCase()

// Same annotation heuristic as the timeline's buildPhases: steps that carry
// their own tactic win; a chain that only reports a top-level tactic list
// has its steps distributed across that list in time order.
function annotateSteps(chain: ChainResultPayload): ChainStep[] {
  const annotated = chain.steps.filter((s) => s.tactic)
  if (annotated.length > 0) return annotated
  const order = chain.tactics ?? []
  if (order.length === 0 || chain.steps.length === 0) return []
  const sorted = [...chain.steps].sort((a, b) => a.ts - b.ts)
  const n = Math.min(order.length, sorted.length)
  const per = Math.ceil(sorted.length / n)
  return sorted.map((s, i) => ({
    ...s,
    tactic: order[Math.min(Math.floor(i / per), n - 1)],
  }))
}

// A MITRE technique as an investigation focus: the same structural facts as
// an AttackPhase but grouped by technique_id instead of tactic, so clicking
// a technique anywhere (ATT&CK ribbon, threat intel) can drive the exact
// same graph/timeline/evidence synchronization. The color is inherited from
// the first phase the technique appears in, keeping one color system.
export interface TechniqueFocus {
  // 'technique:' prefix keeps the id disjoint from phase ids inside the
  // single activeFocusId selection slot.
  id: string
  techniqueId: string
  name: string
  color: string
  eventIds: string[]
  nodeIds: string[]
  edgeIds: string[]
  startTs: number
  endTs: number
  // Phases whose steps carry this technique, usually exactly one.
  phaseIds: string[]
}

export function buildTechniqueFoci(
  chain: ChainResultPayload | null,
  edges: WsEdge[],
  phases: AttackPhase[],
): TechniqueFocus[] {
  if (!chain) return []
  const steps = [...chain.steps].filter((s) => s.technique_id).sort((a, b) => a.ts - b.ts)
  if (steps.length === 0) return []

  const edgesByEvent = new Map<string, WsEdge[]>()
  for (const e of edges) {
    if (!e.source_event_id) continue
    if (!edgesByEvent.has(e.source_event_id)) edgesByEvent.set(e.source_event_id, [])
    edgesByEvent.get(e.source_event_id)!.push(e)
  }

  const order: string[] = []
  const grouped = new Map<string, ChainStep[]>()
  for (const s of steps) {
    const tid = s.technique_id!
    if (!grouped.has(tid)) {
      grouped.set(tid, [])
      order.push(tid)
    }
    grouped.get(tid)!.push(s)
  }

  return order.map((tid) => {
    const techSteps = grouped.get(tid)!
    const eventIds = [...new Set(techSteps.map((s) => s.event_id))]
    const nodeIds = new Set<string>()
    const edgeIds: string[] = []
    for (const eventId of eventIds) {
      for (const e of edgesByEvent.get(eventId) ?? []) {
        edgeIds.push(e.id)
        nodeIds.add(e.src)
        nodeIds.add(e.dst)
      }
    }
    const eventSet = new Set(eventIds)
    const parents = phases.filter((p) => p.eventIds.some((id) => eventSet.has(id)))
    return {
      id: `technique:${tid}`,
      techniqueId: tid,
      name: techSteps[0].technique_name ?? tid,
      color: parents[0]?.color ?? PHASE_COLORS[0],
      eventIds,
      nodeIds: [...nodeIds],
      edgeIds,
      startTs: techSteps[0].ts,
      endTs: techSteps[techSteps.length - 1].ts,
      phaseIds: parents.map((p) => p.id),
    }
  })
}

export function buildAttackPhases(
  chain: ChainResultPayload | null,
  edges: WsEdge[],
  narration: NarrationPayload | null,
): AttackPhase[] {
  if (!chain) return []
  const steps = annotateSteps(chain)
  if (steps.length === 0) return []

  const groups = new Map<string, ChainStep[]>()
  for (const s of steps) {
    const tactic = s.tactic!
    if (!groups.has(tactic)) groups.set(tactic, [])
    groups.get(tactic)!.push(s)
  }
  const tactics = [...groups.keys()].sort(
    (a, b) => Math.min(...groups.get(a)!.map((s) => s.ts)) - Math.min(...groups.get(b)!.map((s) => s.ts)),
  )

  const edgesByEvent = new Map<string, WsEdge[]>()
  for (const e of edges) {
    if (!e.source_event_id) continue
    if (!edgesByEvent.has(e.source_event_id)) edgesByEvent.set(e.source_event_id, [])
    edgesByEvent.get(e.source_event_id)!.push(e)
  }

  return tactics.map((tactic, index) => {
    const phaseSteps = [...groups.get(tactic)!].sort((a, b) => a.ts - b.ts)
    const eventIds = [...new Set(phaseSteps.map((s) => s.event_id))]

    const nodeIds = new Set<string>()
    const edgeIds: string[] = []
    for (const eventId of eventIds) {
      for (const e of edgesByEvent.get(eventId) ?? []) {
        edgeIds.push(e.id)
        nodeIds.add(e.src)
        nodeIds.add(e.dst)
      }
    }

    const techniques: PhaseTechnique[] = []
    const seenTech = new Set<string>()
    for (const s of phaseSteps) {
      if (!s.technique_id || seenTech.has(s.technique_id)) continue
      seenTech.add(s.technique_id)
      techniques.push({ id: s.technique_id, name: s.technique_name ?? s.technique_id })
    }

    const id = phaseSlug(tactic)
    const ai = narration?.phases?.find(
      (p) => p.id === id || normalizeTitle(p.title) === normalizeTitle(tactic),
    )
    const fallback = phaseSteps.slice(0, 2).map((s) => s.description).join('. ') + '.'

    return {
      id,
      title: tactic,
      index,
      color: PHASE_COLORS[index % PHASE_COLORS.length],
      summary: ai?.summary ? ai.summary : fallback,
      aiSummary: Boolean(ai?.summary),
      confidence: phaseSteps.reduce((acc, s) => acc + s.confidence, 0) / phaseSteps.length,
      eventIds,
      nodeIds: [...nodeIds],
      edgeIds,
      startTs: phaseSteps[0].ts,
      endTs: phaseSteps[phaseSteps.length - 1].ts,
      techniques,
      evidenceCount: eventIds.length,
    }
  })
}
