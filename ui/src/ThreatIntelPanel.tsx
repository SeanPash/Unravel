import type { ThreatIntelPayload } from './ws'

export interface ThreatIntelPanelProps {
  intel: ThreatIntelPayload | null
  awaiting: boolean
  hasChain: boolean
  // Techniques the active chain actually contains are navigation: clicking
  // one focuses the workspace on its events. Intel-only techniques (returned
  // by enrichment but absent from the chain) stay inert reference rows.
  onTechniqueSelect?: (techniqueId: string) => void
  activeTechniqueId?: string | null
  chainTechniqueIds?: string[]
}

export function ThreatIntelPanel({
  intel, awaiting, hasChain, onTechniqueSelect, activeTechniqueId, chainTechniqueIds,
}: ThreatIntelPanelProps) {
  if (awaiting) {
    return (
      <div className="intel-panel intel-empty">
        <div className="intel-spinner" aria-label="Gathering threat intel" />
      </div>
    )
  }
  if (!intel) {
    return (
      <div className="intel-panel intel-empty">
        {hasChain ? 'No threat intel returned.' : 'Waiting for chain extraction...'}
      </div>
    )
  }
  if (intel.status === 'error') {
    return (
      <div className="intel-panel intel-error">
        {intel.summary || 'Threat intel enrichment failed.'}
      </div>
    )
  }

  return (
    <div className="intel-panel">
      <p className="intel-summary">{intel.summary}</p>
      <div className="intel-techniques">
        {intel.techniques.map((t) => {
          const navigable = Boolean(onTechniqueSelect) && (chainTechniqueIds ?? []).includes(t.id)
          const active = t.id === activeTechniqueId
          return (
            <div className={`intel-technique${active ? ' intel-technique-active' : ''}`} key={t.id}>
              {navigable ? (
                <button
                  type="button"
                  className="intel-technique-head intel-technique-head-link"
                  aria-pressed={active}
                  title="Focus the investigation on this technique"
                  onClick={() => onTechniqueSelect!(t.id)}
                >
                  <span className="intel-technique-id">{t.id}</span>
                  <span className="intel-technique-name">{t.name}</span>
                </button>
              ) : (
                <div className="intel-technique-head">
                  <span className="intel-technique-id">{t.id}</span>
                  <span className="intel-technique-name">{t.name}</span>
                </div>
              )}
              <IntelRow label="Groups" items={t.groups} />
              <IntelRow label="Tooling" items={t.software} />
              <IntelRow label="Mitigations" items={t.mitigations} />
            </div>
          )
        })}
      </div>
      {intel.cve_matches && intel.cve_matches.length > 0 && (
        <div className="intel-cves">
          <h3>Related vulnerabilities</h3>
          <ul>
            {intel.cve_matches.map((c) => (
              <li key={c.id} className="intel-cve">
                <span className="intel-cve-id">{c.id}</span>
                {c.in_kev && <span className="intel-cve-kev">In KEV</span>}
                {c.severity && <span className="intel-cve-sev">{c.severity}</span>}
                <span className="intel-cve-summary">{c.summary}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

function IntelRow({ label, items }: { label: string; items: string[] }) {
  if (!items || items.length === 0) return null
  return (
    <div className="intel-row">
      <span className="intel-row-label">{label}</span>
      <span className="intel-row-items">{items.join(', ')}</span>
    </div>
  )
}
