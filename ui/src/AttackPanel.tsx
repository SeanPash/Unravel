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
          {byTactic.get(tactic)!.map((s) => {
            const active = s.technique_id !== undefined && s.technique_id === activeTechniqueId
            return (
              <button
                key={s.event_id}
                type="button"
                className={`attack-step ${confidenceClass(s.confidence)}${active ? ' attack-step-active' : ''}`}
                aria-pressed={active}
                onClick={() => {
                  if (s.technique_id && onTechniqueSelect) onTechniqueSelect(s.technique_id)
                  else onNodeFocus(nodeForEvent(edges, s.event_id))
                }}
                title={s.description}
              >
                <span className="attack-step-id">{s.technique_id}</span>
                <span className="attack-step-name">{s.technique_name}</span>
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
