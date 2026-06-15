import { useEffect, useRef, useState, type KeyboardEvent } from 'react'
import { CaretRight } from '@phosphor-icons/react'
import type { AgentActivityPayload } from './ws'
import type { DetailTab } from './DetailTabs'

export interface InvestigationTracePanelProps {
  activity: AgentActivityPayload[]
  busy: boolean
  hasChain: boolean
  // Jump to the detail tab where a step's findings live (Logs for the
  // narrator's raw evidence, Threat Intel for the intel agent's lookups).
  onNavigate?: (tab: DetailTab) => void
}

type StepStatus = 'pending' | 'ok' | 'empty' | 'error' | 'info'

interface TraceStep {
  key: string
  kind: 'tool' | 'done' | 'thinking' | 'error'
  agent: AgentActivityPayload['agent']
  label: string
  tool?: string
  source?: string
  detail?: string
  status: StepStatus
}

// foldActivity collapses the raw call/result stream into one row per tool call:
// a tool_call opens a pending step, the matching tool_result (same tool, most
// recent still-pending) completes it. done/thinking/error events render as
// their own rows. Tool names are disjoint across the two agents, so matching on
// tool name never crosses an agent boundary.
export function foldActivity(activity: AgentActivityPayload[]): TraceStep[] {
  const steps: TraceStep[] = []
  for (const a of activity) {
    const key = `${a.agent}-${a.seq}`
    switch (a.kind) {
      case 'tool_call':
        steps.push({ key, kind: 'tool', agent: a.agent, label: a.label, tool: a.tool, source: a.source, status: 'pending' })
        break
      case 'tool_result': {
        let matched = false
        for (let i = steps.length - 1; i >= 0; i--) {
          if (steps[i].kind === 'tool' && steps[i].status === 'pending' && steps[i].tool === a.tool) {
            steps[i] = { ...steps[i], detail: a.detail, status: a.status ?? 'ok' }
            matched = true
            break
          }
        }
        if (!matched) {
          steps.push({ key, kind: 'tool', agent: a.agent, label: a.label, tool: a.tool, source: a.source, detail: a.detail, status: a.status ?? 'ok' })
        }
        break
      }
      case 'done':
        steps.push({ key, kind: 'done', agent: a.agent, label: a.label, source: a.source, status: 'info' })
        break
      case 'error':
        steps.push({ key, kind: 'error', agent: a.agent, label: a.label, source: a.source, detail: a.detail, status: 'error' })
        break
      case 'thinking':
        steps.push({ key, kind: 'thinking', agent: a.agent, label: a.label, status: 'info' })
        break
    }
  }
  return steps
}

const AGENT_LABEL: Record<string, string> = { narrator: 'Narrator', intel: 'Threat Intel' }

interface StepTarget {
  tab: DetailTab
  label: string
}

// stepTarget points a trace row at the detail tab that holds its output. The
// narrator's tools (process reputation, logon history, raw events, Splunk
// searches) all pull log evidence, so they open the Logs tab; the intel agent's
// lookups (technique intel, KEV, CVE) all surface in the Threat Intel tab. Steps
// without a tool (thinking/done/error) fall back to their agent's home tab.
function stepTarget(step: TraceStep): StepTarget {
  switch (step.tool) {
    case 'lookup_technique_intel':
    case 'lookup_kev':
    case 'search_cve':
      return { tab: 'intel', label: 'Threat Intel' }
    case 'lookup_process_reputation':
    case 'get_account_logon_history':
    case 'fetch_raw_events':
    case 'splunk_search':
    case 'splunk_nl_search':
      return { tab: 'logs', label: 'Logs' }
  }
  return step.agent === 'intel'
    ? { tab: 'intel', label: 'Threat Intel' }
    : { tab: 'logs', label: 'Logs' }
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? '' : 's'}`
}

export function InvestigationTracePanel({ activity, busy, hasChain, onNavigate }: InvestigationTracePanelProps) {
  const steps = foldActivity(activity)
  const toolSteps = steps.filter((s) => s.kind === 'tool')
  const sourceCount = new Set(toolSteps.map((s) => s.source).filter(Boolean)).size

  // Live elapsed timer while the agents are working. startRef is set when the
  // feed first has steps and cleared when it empties (a new extraction starts a
  // fresh run). The interval only ticks while busy, so the value freezes once
  // both agents finish. Elapsed is real wall-clock since the feed began, not a
  // fabricated value.
  const startRef = useRef<number | null>(null)
  const [, setTick] = useState(0)
  useEffect(() => {
    if (steps.length === 0) {
      startRef.current = null
    } else if (startRef.current === null) {
      startRef.current = Date.now()
    }
  }, [steps.length])
  useEffect(() => {
    if (!busy || steps.length === 0) return
    const id = setInterval(() => setTick((t) => t + 1), 200)
    return () => clearInterval(id)
  }, [busy, steps.length])
  const elapsed = startRef.current !== null ? (Date.now() - startRef.current) / 1000 : 0

  return (
    <div className="trace-panel">
      <p className="trace-disclaimer">
        Generated by our agent. Verify findings before acting.
      </p>
      {steps.length > 0 && (
        <div className={`trace-status${busy ? ' trace-status-busy' : ''}`} role="status" aria-live="polite">
          {busy ? (
            <>
              <span className="trace-status-dot" aria-hidden="true" />
              <span className="trace-status-text">
                Investigating - {plural(toolSteps.length, 'lookup')} across {plural(sourceCount, 'source')}
              </span>
              <span className="trace-status-time">{elapsed.toFixed(1)}s</span>
            </>
          ) : (
            <span className="trace-status-text">
              Investigation complete - {plural(toolSteps.length, 'lookup')} across {plural(sourceCount, 'source')}
            </span>
          )}
        </div>
      )}
      {steps.length === 0 ? (
        <div className="trace-empty">
          {!hasChain
            ? 'Waiting for chain extraction...'
            : busy
              ? 'Agents starting investigation...'
              : 'No agent activity for this incident.'}
        </div>
      ) : (
        <ol className="trace-feed">
          {steps.map((s) => {
            const target = onNavigate ? stepTarget(s) : null
            const navProps = target
              ? {
                  role: 'button' as const,
                  tabIndex: 0,
                  title: `Open this finding in ${target.label}`,
                  onClick: () => onNavigate?.(target.tab),
                  onKeyDown: (e: KeyboardEvent) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault()
                      onNavigate?.(target.tab)
                    }
                  },
                }
              : {}
            return (
              <li
                key={s.key}
                className={`trace-step trace-step-${s.status} trace-step-kind-${s.kind}${target ? ' trace-step-nav' : ''}`}
                {...navProps}
              >
                <div className="trace-step-head">
                  <span className={`trace-agent trace-agent-${s.agent}`}>{AGENT_LABEL[s.agent] ?? s.agent}</span>
                  {s.source && <span className="trace-source">{s.source}</span>}
                  <span className="trace-label">{s.label}</span>
                  {s.status === 'pending' && <span className="trace-spinner" aria-label="working" />}
                  {target && (
                    <span className="trace-step-go" aria-hidden="true">
                      {target.label}
                      <CaretRight size={10} weight="bold" />
                    </span>
                  )}
                </div>
                {s.detail && <div className="trace-detail">{s.detail}</div>}
              </li>
            )
          })}
        </ol>
      )}
    </div>
  )
}
