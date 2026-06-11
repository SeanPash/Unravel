import type { IncidentState } from './App'

export interface IncidentListProps {
  incidents: IncidentState[]
  activeIncidentId: string | null
  onSelect: (id: string) => void
}

export function IncidentList({ incidents, activeIncidentId, onSelect }: IncidentListProps) {
  if (incidents.length === 0) {
    return (
      <div className="incident-list incident-list-empty">
        <p>No incidents yet</p>
      </div>
    )
  }

  const sorted = [...incidents].sort((a, b) => a.firstSeen - b.firstSeen)

  return (
    <div className="incident-list" role="listbox" aria-label="Incidents">
      {sorted.map((inc) => (
        <button
          key={inc.id}
          type="button"
          role="option"
          aria-selected={inc.id === activeIncidentId}
          className={`incident-row${inc.id === activeIncidentId ? ' incident-row-active' : ''}`}
          onClick={() => onSelect(inc.id)}
        >
          <span className="incident-row-label">{inc.label}</span>
          <span className="incident-row-meta">
            {inc.chain
              ? `${inc.chain.steps.length} steps - ${Math.round(inc.chain.confidence * 100)}%`
              : 'pending'}
          </span>
        </button>
      ))}
    </div>
  )
}
