// Investigation drawer for the focused graph node. Replaces the old raw
// attrs tooltip: instead of describing the node it explains its role in the
// attack (the engine's own chain step wording), where it sits (phases,
// techniques), what it touches (parents and children), and what evidence
// backs it. Every chip and relation row is a navigation into the existing
// focus machinery, so the inspector is a hub, not a dead end.

import { X, ArrowElbowDownRight, ArrowElbowLeftUp } from '@phosphor-icons/react'
import type { NodeContext, NodeRelation } from './nodeContext'
import type { AttackPhase } from './attackPhases'
import { shortenNodeLabel } from './GraphView'

export interface NodeInspectorProps {
  context: NodeContext
  onClose: () => void
  onNodeFocus: (nodeId: string) => void
  onPhaseSelect: (phase: AttackPhase) => void
  onTechniqueSelect: (techniqueId: string) => void
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

const ATTR_LABELS: Record<string, string> = {
  pid: 'PID',
  host: 'Host',
  ip: 'IP',
  ts: 'First seen',
  proto: 'Protocol',
  dst_port: 'Dst port',
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
        <Arrow size={11} aria-hidden="true" />
        <span className="inspector-relation-kind">{rel.kind.replaceAll('_', ' ')}</span>
        <span className="inspector-relation-label">{shortenNodeLabel(rel.node.label)}</span>
      </button>
    </li>
  )
}

export function NodeInspector({ context, onClose, onNodeFocus, onPhaseSelect, onTechniqueSelect }: NodeInspectorProps) {
  const { node, parents, children, phases, techniques, chainDescriptions, onAttackPath, maxConfidence, evidenceCount } = context
  const attrs = Object.entries(node.attrs)

  return (
    <aside className="node-inspector" aria-label="Node details">
      <header className="inspector-head">
        <div className="inspector-title">
          <span className={`inspector-kind inspector-kind-${node.kind.toLowerCase()}`}>{node.kind}</span>
          <span className="inspector-name" title={node.label}>{shortenNodeLabel(node.label)}</span>
        </div>
        <button type="button" className="inspector-close" aria-label="Close node details" onClick={onClose}>
          <X size={12} />
        </button>
      </header>

      <section className="inspector-section">
        <div className="inspector-section-head">
          <h3>Role in attack</h3>
          {maxConfidence > 0 && (
            <span className={`inspector-conf phase-card-conf-${confidenceBand(maxConfidence)}`}>
              {Math.round(maxConfidence * 100)}%
            </span>
          )}
        </div>
        {onAttackPath ? (
          <ul className="inspector-role">
            {chainDescriptions.map((d) => <li key={d}>{d}</li>)}
          </ul>
        ) : (
          <p className="inspector-quiet">Not on the extracted attack path. Activity near this node is background noise so far.</p>
        )}
      </section>

      {(phases.length > 0 || techniques.length > 0) && (
        <section className="inspector-section">
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
        </section>
      )}

      {(parents.length > 0 || children.length > 0) && (
        <section className="inspector-section">
          <h3>Connections</h3>
          <ul className="inspector-relations">
            {parents.map((r) => (
              <RelationRow key={`p-${r.node.id}-${r.kind}`} rel={r} direction="parent" onNodeFocus={onNodeFocus} />
            ))}
            {children.map((r) => (
              <RelationRow key={`c-${r.node.id}-${r.kind}`} rel={r} direction="child" onNodeFocus={onNodeFocus} />
            ))}
          </ul>
        </section>
      )}

      {attrs.length > 0 && (
        <section className="inspector-section">
          <h3>Identity</h3>
          <dl className="inspector-attrs">
            {attrs.map(([k, v]) => (
              <div key={k} className="inspector-attr">
                <dt>{ATTR_LABELS[k] ?? k}</dt>
                <dd>{formatAttr(k, v)}</dd>
              </div>
            ))}
          </dl>
        </section>
      )}

      <footer className="inspector-foot">
        {evidenceCount > 0
          ? `${evidenceCount} raw event${evidenceCount === 1 ? '' : 's'} in the Logs tab`
          : 'No raw events recorded yet'}
      </footer>
    </aside>
  )
}
