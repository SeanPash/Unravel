import { describe, it, expect } from 'vitest'
import { render } from '@testing-library/react'
import { InvestigationTracePanel, foldActivity } from '../InvestigationTracePanel'
import type { AgentActivityPayload } from '../ws'

const call = (overrides: Partial<AgentActivityPayload>): AgentActivityPayload => ({
  agent: 'narrator',
  seq: 0,
  kind: 'tool_call',
  label: 'Checking lsass.exe',
  tool: 'lookup_process_reputation',
  source: 'Splunk threat_intel index',
  ...overrides,
})

describe('foldActivity', () => {
  it('collapses a call and its result into one completed step', () => {
    const steps = foldActivity([
      call({ seq: 0, kind: 'tool_call' }),
      call({ seq: 1, kind: 'tool_result', detail: 'flagged malicious', status: 'ok' }),
    ])
    expect(steps).toHaveLength(1)
    expect(steps[0].status).toBe('ok')
    expect(steps[0].detail).toBe('flagged malicious')
  })

  it('leaves an unmatched call pending', () => {
    const steps = foldActivity([call({ seq: 0, kind: 'tool_call' })])
    expect(steps).toHaveLength(1)
    expect(steps[0].status).toBe('pending')
  })

  it('matches results to calls by tool, not position', () => {
    const steps = foldActivity([
      call({ seq: 0, kind: 'tool_call', tool: 'lookup_kev', source: 'CISA KEV', label: 'KEV' }),
      call({ seq: 1, kind: 'tool_call', tool: 'search_cve', source: 'NVD', label: 'NVD' }),
      call({ seq: 2, kind: 'tool_result', tool: 'search_cve', source: 'NVD', label: 'NVD', detail: '2 matches', status: 'ok' }),
    ])
    expect(steps).toHaveLength(2)
    expect(steps.find((s) => s.label === 'NVD')?.status).toBe('ok')
    expect(steps.find((s) => s.label === 'KEV')?.status).toBe('pending')
  })
})

describe('InvestigationTracePanel', () => {
  it('shows the AI disclaimer', () => {
    const { container } = render(<InvestigationTracePanel activity={[]} busy={false} hasChain />)
    expect(container.querySelector('.trace-disclaimer')?.textContent).toMatch(/verify findings/i)
  })

  it('renders a spinner for a still-pending tool call', () => {
    const { container } = render(
      <InvestigationTracePanel activity={[call({ seq: 0, kind: 'tool_call' })]} busy hasChain />,
    )
    expect(container.querySelector('.trace-spinner')).toBeTruthy()
  })

  it('renders the result detail once it arrives', () => {
    const { getByText } = render(
      <InvestigationTracePanel
        activity={[
          call({ seq: 0, kind: 'tool_call' }),
          call({ seq: 1, kind: 'tool_result', detail: 'flagged malicious', status: 'ok' }),
        ]}
        busy={false}
        hasChain
      />,
    )
    expect(getByText('flagged malicious')).toBeTruthy()
  })
})
