// Investigation drawer for the focused graph node. Replaces the old raw
// attrs tooltip: instead of describing the node it explains its role in the
// attack (the engine's own chain step wording), where it sits (phases,
// techniques), what it touches (parents and children), and the actual raw
// events behind it. Every chip, relation row, and evidence row is a
// navigation into the existing focus machinery, so the inspector is a hub,
// not a dead end.

import { useState } from 'react'
import {
  X, ArrowElbowDownRight, ArrowElbowLeftUp, ArrowSquareOut, CaretRight,
  Crosshair, Stack, FileMagnifyingGlass, IdentificationCard,
} from '@phosphor-icons/react'
import type { NodeContext, NodeRelation, EvidenceItem } from './nodeContext'
import type { AttackPhase } from './attackPhases'
import { shortenNodeLabel } from './GraphView'

export interface NodeInspectorProps {
  context: NodeContext
  onClose: () => void
  onNodeFocus: (nodeId: string) => void
  onPhaseSelect: (phase: AttackPhase) => void
  onTechniqueSelect: (techniqueId: string) => void
  // Open a raw event elsewhere in the app (Logs tab + timeline moment).
  onEventOpen?: (eventId: string, ts: number) => void
  // Floating-panel plumbing supplied by the host: absolute position and
  // stacking via style, drag handling on the header, bring-to-front on any
  // press, and the focused accent for the node driving the Logs tab.
  style?: React.CSSProperties
  headerProps?: React.HTMLAttributes<HTMLElement>
  onPanelPointerDown?: (e: React.PointerEvent) => void
  focused?: boolean
}

// Per-kind accent, mirrored from the graph palette so a panel is recognisable
// as the same node it sprang from.
const KIND_ACCENT: Record<NodeContext['node']['kind'], string> = {
  Process: '#4fa7d9',
  Host: '#53a051',
  User: '#f0b429',
  NetFlow: '#9d7cd8',
}

function confidenceBand(c: number): 'high' | 'medium' | 'low' {
  if (c >= 0.8) return 'high'
  if (c >= 0.6) return 'medium'
  return 'low'
}

function formatAttr(key: string, value: unknown): string {
  if (key === 'ts' && typeof value === 'number') {
    return new Date(value * 1000).toISOString().replace('T', ' ').slice(0, 19)
  }
  return String(value)
}

// Evidence rows are time-only: the incident date is shared, so the hour is
// what distinguishes one event from the next.
function formatClock(ts: number): string {
  return new Date(ts * 1000).toISOString().slice(11, 19)
}

const ATTR_LABELS: Record<string, string> = {
  pid: 'PID',
  host: 'Host',
  ip: 'IP',
  ts: 'First seen',
  proto: 'Protocol',
  dst_port: 'Dst port',
}

// A titled block with a colored tick, so each section reads as its own card
// and the boundary between sections is unmistakable.
function Section({
  icon, title, meta, accent, variant, children,
}: {
  icon: React.ReactNode
  title: string
  meta?: React.ReactNode
  accent?: string
  variant?: 'inset'
  children: React.ReactNode
}) {
  return (
    <section className={`inspector-section${variant === 'inset' ? ' inspector-section-inset' : ''}`}>
      <div className="inspector-sec-head" style={accent ? { '--sec-accent': accent } as React.CSSProperties : undefined}>
        <span className="inspector-sec-tick" aria-hidden="true">{icon}</span>
        <h3>{title}</h3>
        {meta !== undefined && <span className="inspector-sec-meta">{meta}</span>}
      </div>
      {children}
    </section>
  )
}

function RelationRow({ rel, direction, onNodeFocus }: {
  rel: NodeRelation
  direction: 'parent' | 'child'
  onNodeFocus: (nodeId: string) => void
}) {
  const Arrow = direction === 'parent' ? ArrowElbowLeftUp : ArrowElbowDownRight
  return (
    <li>
      <button type="button" className="inspector-relation" onClick={() => onNodeFocus(rel.node.id)}>
        <Arrow size={12} weight="bold" aria-hidden="true" />
        <span className="inspector-relation-kind">{rel.kind.replaceAll('_', ' ')}</span>
        <span className="inspector-relation-label">{shortenNodeLabel(rel.node.label)}</span>
      </button>
    </li>
  )
}

function EvidenceRow({ item, expanded, onToggle, onOpen }: {
  item: EvidenceItem
  expanded: boolean
  onToggle: () => void
  onOpen?: () => void
}) {
  const rawEntries = Object.entries(item.raw)
  return (
    <li className={`inspector-evidence${expanded ? ' inspector-evidence-open' : ''}`}>
      <div className="inspector-evidence-row">
        <button type="button" className="inspector-evidence-main" onClick={onToggle} aria-expanded={expanded}>
          <CaretRight size={10} weight="bold" className="inspector-evidence-caret" aria-hidden="true" />
          <span className="inspector-evidence-ts">{formatClock(item.ts)}</span>
          <span className="inspector-evidence-src">{item.source}</span>
          <span className="inspector-evidence-text">{item.summary || item.eventId}</span>
        </button>
        {onOpen && (
          <button
            type="button"
            className="inspector-evidence-open-btn"
            title="Open this event in the Logs tab"
            aria-label="Open this event in the Logs tab"
            onClick={onOpen}
          >
            <ArrowSquareOut size={13} />
          </button>
        )}
      </div>
      {expanded && rawEntries.length > 0 && (
        <dl className="inspector-evidence-detail">
          {rawEntries.map(([k, v]) => (
            <div key={k} className="inspector-evidence-field">
              <dt>{k}</dt>
              <dd>{formatAttr(k, v)}</dd>
            </div>
          ))}
        </dl>
      )}
    </li>
  )
}

export function NodeInspector({
  context, onClose, onNodeFocus, onPhaseSelect, onTechniqueSelect, onEventOpen,
  style, headerProps, onPanelPointerDown, focused,
}: NodeInspectorProps) {
  const {
    node, parents, children, phases, techniques, chainDescriptions,
    onAttackPath, maxConfidence, evidence,
  } = context
  const attrs = Object.entries(node.attrs)
  const kindAccent = KIND_ACCENT[node.kind] ?? '#8a99a8'
  const connectionCount = parents.length + children.length

  const [openEvidenceId, setOpenEvidenceId] = useState<string | null>(null)

  return (
    <aside
      className={`node-inspector${focused ? ' node-inspector-focused' : ''}`}
      aria-label="Node details"
      style={{ ...style, '--kind-accent': kindAccent } as React.CSSProperties}
      onPointerDown={onPanelPointerDown}
    >
      <header className="inspector-head" {...headerProps}>
        <div className="inspector-title">
          <span className={`inspector-kind inspector-kind-${node.kind.toLowerCase()}`}>{node.kind}</span>
          <span className="inspector-name" title={node.label}>{shortenNodeLabel(node.label)}</span>
        </div>
        <span className="inspector-head-right">
          {focused && <span className="inspector-focus-badge">Focused</span>}
          <button type="button" className="inspector-close" aria-label="Close node details" onClick={onClose}>
            <X size={13} weight="bold" />
          </button>
        </span>
      </header>

      <div className="inspector-body">
        <Section
          icon={<Crosshair size={12} weight="bold" />}
          title="Role in attack"
          accent={kindAccent}
          meta={maxConfidence > 0 ? (
            <span className={`inspector-conf inspector-conf-${confidenceBand(maxConfidence)}`}>
              {Math.round(maxConfidence * 100)}%
            </span>
          ) : undefined}
        >
          {onAttackPath ? (
            <div className={`inspector-role-callout inspector-role-${confidenceBand(maxConfidence)}`}>
              <ul className="inspector-role">
                {chainDescriptions.map((d) => <li key={d}>{d}</li>)}
              </ul>
            </div>
          ) : (
            <p className="inspector-quiet">
              Not on the extracted attack path. Activity near this node is background noise so far.
            </p>
          )}
          {(phases.length > 0 || techniques.length > 0) && (
            <div className="inspector-chips">
              {phases.map((p) => (
                <button
                  key={p.id}
                  type="button"
                  className="inspector-chip"
                  style={{ '--phase-accent': p.color } as React.CSSProperties}
                  title={`Focus the ${p.title} phase`}
                  onClick={() => onPhaseSelect(p)}
                >
                  {p.title}
                </button>
              ))}
              {techniques.map((t) => (
                <button
                  key={t.techniqueId}
                  type="button"
                  className="inspector-chip inspector-chip-tech"
                  style={{ '--phase-accent': t.color } as React.CSSProperties}
                  title={`Focus ${t.name}`}
                  onClick={() => onTechniqueSelect(t.techniqueId)}
                >
                  {t.techniqueId}
                </button>
              ))}
            </div>
          )}
        </Section>

        {connectionCount > 0 && (
          <Section
            icon={<Stack size={12} weight="bold" />}
            title="Connections"
            accent={kindAccent}
            meta={<span className="inspector-count">{connectionCount}</span>}
          >
            <ul className="inspector-relations">
              {parents.map((r) => (
                <RelationRow key={`p-${r.node.id}-${r.kind}`} rel={r} direction="parent" onNodeFocus={onNodeFocus} />
              ))}
              {children.map((r) => (
                <RelationRow key={`c-${r.node.id}-${r.kind}`} rel={r} direction="child" onNodeFocus={onNodeFocus} />
              ))}
            </ul>
          </Section>
        )}

        {attrs.length > 0 && (
          <Section
            icon={<IdentificationCard size={12} weight="bold" />}
            title="Identity"
            accent={kindAccent}
            variant="inset"
          >
            <dl className="inspector-attrs">
              {attrs.map(([k, v]) => (
                <div key={k} className="inspector-attr">
                  <dt>{ATTR_LABELS[k] ?? k}</dt>
                  <dd>{formatAttr(k, v)}</dd>
                </div>
              ))}
            </dl>
          </Section>
        )}

        <Section
          icon={<FileMagnifyingGlass size={12} weight="bold" />}
          title="Evidence"
          accent={kindAccent}
          variant="inset"
          meta={<span className="inspector-count">{evidence.length}</span>}
        >
          {evidence.length > 0 ? (
            <ul className="inspector-evidence-list">
              {evidence.map((item) => (
                <EvidenceRow
                  key={item.eventId}
                  item={item}
                  expanded={openEvidenceId === item.eventId}
                  onToggle={() => setOpenEvidenceId((id) => (id === item.eventId ? null : item.eventId))}
                  onOpen={onEventOpen ? () => onEventOpen(item.eventId, item.ts) : undefined}
                />
              ))}
            </ul>
          ) : (
            <p className="inspector-quiet">No raw events recorded for this node yet.</p>
          )}
        </Section>
      </div>
    </aside>
  )
}
