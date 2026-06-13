import { useState } from 'react'
import type { LogEventPayload } from './ws'
import type { RelatedLog } from './logFilter'
import { summarizeLog } from './logFilter'
import { phaseColorAt } from './timeline'
import type { TimelinePhase } from './timeline'

// Kept as a named re-export so existing importers (and tests) keep working;
// the implementation now lives in logFilter so non-React code can share it.
export const summarize = summarizeLog

export interface LogsPanelProps {
  logs: RelatedLog[]
  focusedLabel: string | null
  hasChain: boolean
  onClearFocus: () => void
  // Attack phases of the active incident; rows take their phase's color.
  phases?: TimelinePhase[]
  // Clicking a row also drives the timeline to the log's moment.
  onLogSelect?: (log: LogEventPayload) => void
}

function formatTs(ts: number): string {
  return new Date(ts * 1000).toISOString().replace('T', ' ').slice(0, 19)
}

export function LogsPanel({ logs, focusedLabel, hasChain, onClearFocus, phases = [], onLogSelect }: LogsPanelProps) {
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
            {logs.map(({ log, onChain }) => {
              const phaseColor = phaseColorAt(phases, log.ts)
              // The chain accent stripe only shows while an incident node or
              // event is focused; the resting list stays quiet.
              const accented = onChain && focusedLabel !== null
              return (
                <li
                  key={log.event_id}
                  className={`logs-row${accented ? ' logs-row-chain' : ''}`}
                  style={phaseColor !== null ? { '--row-accent': phaseColor } as React.CSSProperties : undefined}
                >
                  <button
                    type="button"
                    className="logs-row-summary"
                    onClick={() => {
                      setExpandedId(expandedId === log.event_id ? null : log.event_id)
                      onLogSelect?.(log)
                    }}
                  >
                    <span className="logs-row-ts">{formatTs(log.ts)}</span>
                    <span className="logs-row-source">{log.source}</span>
                    <span className="logs-row-text">{summarize(log)}</span>
                  </button>
                  {expandedId === log.event_id && (
                    <pre className="logs-row-raw">{JSON.stringify(log.raw, null, 2)}</pre>
                  )}
                </li>
              )
            })}
          </ul>
        )}
      </div>
    </section>
  )
}
