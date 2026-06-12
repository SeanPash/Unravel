import type { ChainResultPayload, ChainStep, WsEdge } from './ws'
import { nodeForEvent } from './logFilter'

export interface AttackPanelProps {
  chain: ChainResultPayload | null
  edges: WsEdge[]
  onNodeFocus: (nodeId: string | null) => void
  // Selecting a technique synchronizes the whole workspace around it (graph,
  // timeline, evidence), the same focus mechanism the phase cards use. Steps
  // without a technique fall back to plain node focus.
  onTechniqueSelect?: (techniqueId: string) => void
  activeTechniqueId?: string | null
}

// confidenceClass buckets a 0-1 score into a CSS modifier so cells shade from
// low to high without inline styles.
function confidenceClass(c: number): string {
  if (c >= 0.85) return 'attack-step-high'
  if (c >= 0.6) return 'attack-step-med'
  return 'attack-step-low'
}

export function AttackPanel({ chain, edges, onNodeFocus, onTechniqueSelect, activeTechniqueId }: AttackPanelProps) {
  if (!chain || chain.steps.length === 0) {
    return <div className="attack-empty">Waiting for chain extraction...</div>
  }

  // Group steps under their tactic, preserving chain.tactics (chain) ordering.
  const tactics = chain.tactics && chain.tactics.length > 0
    ? chain.tactics
    : distinctTactics(chain.steps)

  const byTactic = new Map<string, ChainStep[]>()
  for (const t of tactics) byTactic.set(t, [])
  const unmapped: ChainStep[] = []
  for (const s of chain.steps) {
    if (s.tactic && byTactic.has(s.tactic)) byTactic.get(s.tactic)!.push(s)
    else unmapped.push(s)
  }

  return (
    <div className="attack-ribbon">
      {tactics.map((tactic, ti) => (
        <div className="attack-tactic" key={tactic}>
          <div className="attack-tactic-head">
            <span className="attack-tactic-index">{ti + 1}</span>
            <span className="attack-tactic-name">{tactic}</span>
          </div>
          {groupByTechnique(byTactic.get(tactic)!).map((g) => {
            const active = g.techniqueId !== undefined && g.techniqueId === activeTechniqueId
            return (
              <button
                key={g.techniqueId ?? g.steps[0].event_id}
                type="button"
                className={`attack-step ${confidenceClass(g.confidence)}${active ? ' attack-step-active' : ''}`}
                aria-pressed={active}
                onClick={() => {
                  if (g.techniqueId && onTechniqueSelect) onTechniqueSelect(g.techniqueId)
                  else onNodeFocus(nodeForEvent(edges, g.steps[0].event_id))
                }}
                title={g.steps.map((s) => s.description).join('\n')}
              >
                <span className="attack-step-id">{g.techniqueId}</span>
                <span className="attack-step-name">{g.steps[0].technique_name}</span>
                {g.steps.length > 1 && (
                  <span className="attack-step-count">{g.steps.length} events</span>
                )}
              </button>
            )
          })}
        </div>
      ))}
      {unmapped.length > 0 && (
        <div className="attack-tactic attack-tactic-unmapped">
          <div className="attack-tactic-head"><span className="attack-tactic-name">Unmapped</span></div>
          {unmapped.map((s) => (
            <button
              key={s.event_id}
              type="button"
              className="attack-step attack-step-unmapped"
              onClick={() => onNodeFocus(nodeForEvent(edges, s.event_id))}
              title={s.description}
            >
              <span className="attack-step-name">{s.description}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

interface TechniqueGroup {
  techniqueId?: string
  steps: ChainStep[]
  // Strongest observation of the technique, shading the cell.
  confidence: number
}

// One cell per technique within a tactic: a technique observed by several
// chain steps (e.g. two LSASS reads) is a single entry with an event count,
// not a duplicated row. Steps with no technique stay one cell each.
function groupByTechnique(steps: ChainStep[]): TechniqueGroup[] {
  const order: TechniqueGroup[] = []
  const byId = new Map<string, TechniqueGroup>()
  for (const s of steps) {
    if (!s.technique_id) {
      order.push({ steps: [s], confidence: s.confidence })
      continue
    }
    const existing = byId.get(s.technique_id)
    if (existing) {
      existing.steps.push(s)
      existing.confidence = Math.max(existing.confidence, s.confidence)
    } else {
      const g: TechniqueGroup = { techniqueId: s.technique_id, steps: [s], confidence: s.confidence }
      byId.set(s.technique_id, g)
      order.push(g)
    }
  }
  return order
}

function distinctTactics(steps: ChainStep[]): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const s of steps) {
    if (s.tactic && !seen.has(s.tactic)) {
      seen.add(s.tactic)
      out.push(s.tactic)
    }
  }
  return out
}
