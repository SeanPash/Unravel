import { useState } from 'react'
import type { LogEventPayload } from './ws'
import type { RelatedLog } from './logFilter'

export interface LogsPanelProps {
  logs: RelatedLog[]
  focusedLabel: string | null
  hasChain: boolean
  onClearFocus: () => void
}

// One line of human-readable context per raw event. Field names differ per
// source (Sysmon vs Windows Security), so try the common ones in order.
export function summarize(log: LogEventPayload): string {
  const r = log.raw
  const host = r['host'] ?? r['Computer']
  const subject = r['Image'] ?? r['TargetUserName'] ?? r['TargetFilename'] ?? r['SourceImage']
  const cmd = r['CommandLine']
  return [host, subject, cmd].filter(Boolean).map(String).join('  ')
}

function formatTs(ts: number): string {
  return new Date(ts * 1000).toISOString().replace('T', ' ').slice(0, 19)
}

export function LogsPanel({ logs, focusedLabel, hasChain, onClearFocus }: LogsPanelProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null)

  return (
    <section className="dash-panel logs-pane">
      <div className="dash-panel-title logs-title">
        <span>{focusedLabel !== null ? `Logs: ${focusedLabel}` : 'Related Logs'}</span>
        {focusedLabel !== null && (
          <button type="button" className="logs-clear-filter" onClick={onClearFocus}>
            Clear filter
          </button>
        )}
      </div>
      <div className="dash-panel-body logs-body">
        {logs.length === 0 ? (
          <div className="logs-empty">
            {focusedLabel !== null
              ? 'No logs for this node'
              : hasChain
                ? 'No logs matched the chain'
                : 'Waiting for chain extraction...'}
          </div>
        ) : (
          <ul className="logs-list">
            {logs.map(({ log, onChain }) => (
              <li key={log.event_id} className={`logs-row${onChain ? ' logs-row-chain' : ''}`}>
                <button
                  type="button"
                  className="logs-row-summary"
                  onClick={() => setExpandedId(expandedId === log.event_id ? null : log.event_id)}
                >
                  <span className="logs-row-ts">{formatTs(log.ts)}</span>
                  <span className="logs-row-source">{log.source}</span>
                  <span className="logs-row-text">{summarize(log)}</span>
                </button>
                {expandedId === log.event_id && (
                  <pre className="logs-row-raw">{JSON.stringify(log.raw, null, 2)}</pre>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  )
}
