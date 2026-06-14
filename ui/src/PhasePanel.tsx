// Attack phase investigation panel: one card per attack phase, clickable to
// drive the graph camera, timeline, and evidence views to that phase. The
// cards are the AI Narration panel's replacement; the narrative is broken
// into per-phase summaries with the structural facts (confidence, techniques,
// evidence counts) coming straight from the engine's chain.

import type { Icon } from '@phosphor-icons/react'
import {
  ArrowFatLineUp,
  ArrowsLeftRight,
  Binoculars,
  Broadcast,
  CastleTurret,
  Crosshair,
  EnvelopeSimpleOpen,
  EyeSlash,
  Key,
  PushPin,
  Terminal,
  Tray,
  UploadSimple,
  WarningDiamond,
} from '@phosphor-icons/react'
import type { AttackPhase } from './attackPhases'
import type { NarrationPayload } from './ws'

export interface PhasePanelProps {
  phases: AttackPhase[]
  // The workspace's single focus slot: a phase id, or 'technique:<id>' when
  // the focus came from a MITRE surface.
  activeFocusId: string | null
  // When a technique is the focus, its chips and parent cards light up here
  // so the panel answers the selection made elsewhere.
  activeTechnique?: { techniqueId: string; phaseIds: string[] } | null
  narration: NarrationPayload | null
  awaitingNarration: boolean
  onPhaseSelect: (phase: AttackPhase | null) => void
}

// MITRE tactic -> glyph. Keyed by the kebab-case phase id so renamed display
// titles cannot break the mapping.
const TACTIC_ICONS: Record<string, Icon> = {
  'initial-access': EnvelopeSimpleOpen,
  'execution': Terminal,
  'persistence': PushPin,
  'privilege-escalation': ArrowFatLineUp,
  'defense-evasion': EyeSlash,
  'credential-access': Key,
  'credential-theft': Key,
  'discovery': Binoculars,
  'lateral-movement': ArrowsLeftRight,
  'collection': Tray,
  'command-and-control': Broadcast,
  'exfiltration': UploadSimple,
  'impact': WarningDiamond,
  'domain-compromise': CastleTurret,
  'kerberos-abuse': Key,
}

const MAX_TECH_BADGES = 2

function confidenceBand(c: number): 'high' | 'medium' | 'low' {
  if (c >= 0.8) return 'high'
  if (c >= 0.6) return 'medium'
  return 'low'
}

export function PhasePanel({ phases, activeFocusId, activeTechnique, narration, awaitingNarration, onPhaseSelect }: PhasePanelProps) {
  if (phases.length === 0) {
    if (awaitingNarration) {
      return (
        <div className="phase-panel">
          <div className="narration-spinner" aria-label="Awaiting narration" />
        </div>
      )
    }
    return (
      <div className="phase-panel phase-panel-empty">
        <p>Waiting for causal chain...</p>
      </div>
    )
  }

  return (
    <div className="phase-panel">
      <ol className="phase-list">
        {phases.map((p) => {
          const Glyph = TACTIC_ICONS[p.id] ?? Crosshair
          const active = p.id === activeFocusId
          // A phase is "related" when the focused technique lives inside it.
          const related = !active && (activeTechnique?.phaseIds.includes(p.id) ?? false)
          const pendingSummary = awaitingNarration && !p.aiSummary
          const extraTech = p.techniques.length - MAX_TECH_BADGES
          return (
            <li key={p.id}>
              <button
                type="button"
                className={`phase-card${active ? ' phase-card-active' : ''}${related ? ' phase-card-related' : ''}`}
                style={{ '--phase-accent': p.color } as React.CSSProperties}
                aria-pressed={active}
                onClick={() => onPhaseSelect(active ? null : p)}
              >
                <span className="phase-card-icon" aria-hidden="true">
                  <Glyph size={15} weight={active ? 'fill' : 'regular'} />
                </span>
                <span className="phase-card-main">
                  <span className="phase-card-head">
                    <span className="phase-card-title">{p.title}</span>
                    <span className={`phase-card-conf phase-card-conf-${confidenceBand(p.confidence)}`}>
                      {Math.round(p.confidence * 100)}%
                    </span>
                  </span>
                  <span className={`phase-card-summary${pendingSummary ? ' phase-card-summary-pending' : ''}`}>
                    {p.summary}
                  </span>
                  <span className="phase-card-meta">
                    {p.techniques.slice(0, MAX_TECH_BADGES).map((t) => (
                      <span
                        key={t.id}
                        className={`phase-card-tech${t.id === activeTechnique?.techniqueId ? ' phase-card-tech-active' : ''}`}
                        title={t.name}
                      >
                        {t.id}
                      </span>
                    ))}
                    {extraTech > 0 && <span className="phase-card-tech phase-card-tech-more">+{extraTech}</span>}
                    <span className="phase-card-evidence">
                      {p.evidenceCount} {p.evidenceCount === 1 ? 'event' : 'events'}
                    </span>
                  </span>
                </span>
              </button>
            </li>
          )
        })}
      </ol>

      {narration && narration.hypotheses.length > 0 && (
        <section className="phase-notes">
          <h3>Missing evidence</h3>
          <ul className="narration-hypotheses">
            {narration.hypotheses.map((h, i) => <li key={i}>{h}</li>)}
          </ul>
        </section>
      )}
      {narration && narration.actions.length > 0 && (
        <section className="phase-notes">
          <h3>Containment actions</h3>
          <ol className="narration-actions">
            {narration.actions.map((a, i) => <li key={i}>{a}</li>)}
          </ol>
        </section>
      )}
      <p className="phase-disclaimer">
        Agent generated these findings. Make sure to verify them.
      </p>
    </div>
  )
}
