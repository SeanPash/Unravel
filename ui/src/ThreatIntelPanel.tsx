import type { ThreatIntelPayload } from './ws'

export interface ThreatIntelPanelProps {
  intel: ThreatIntelPayload | null
  awaiting: boolean
  hasChain: boolean
}

export function ThreatIntelPanel({ intel, awaiting, hasChain }: ThreatIntelPanelProps) {
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
        {intel.techniques.map((t) => (
          <div className="intel-technique" key={t.id}>
            <div className="intel-technique-head">
              <span className="intel-technique-id">{t.id}</span>
              <span className="intel-technique-name">{t.name}</span>
            </div>
            <IntelRow label="Groups" items={t.groups} />
            <IntelRow label="Tooling" items={t.software} />
            <IntelRow label="Mitigations" items={t.mitigations} />
          </div>
        ))}
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
