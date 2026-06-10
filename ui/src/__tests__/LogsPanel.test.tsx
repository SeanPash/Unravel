import { describe, it, expect, vi } from 'vitest'
import { render, fireEvent } from '@testing-library/react'
import { LogsPanel, summarize } from '../LogsPanel'
import type { RelatedLog } from '../logFilter'

const row = (id: string, ts: number, onChain: boolean, raw: Record<string, unknown> = {}): RelatedLog => ({
  log: {
    event_id: id,
    ts,
    source: 'sysmon',
    raw: { host: 'WS01', Image: 'C:\\Windows\\System32\\powershell.exe', ...raw },
  },
  onChain,
})

describe('summarize', () => {
  it('joins host, image, and command line when present', () => {
    const s = summarize(row('evt-1', 100, true, { CommandLine: 'powershell.exe -enc AAA' }).log)
    expect(s).toContain('WS01')
    expect(s).toContain('powershell.exe')
    expect(s).toContain('-enc AAA')
  })

  it('omits absent fields without leaving gaps', () => {
    const s = summarize({ event_id: 'e', ts: 1, source: 'winsec', raw: { host: 'DC01' } })
    expect(s).toBe('DC01')
  })
})

describe('LogsPanel', () => {
  it('shows the waiting state before any chain exists', () => {
    const { getByText } = render(
      <LogsPanel logs={[]} focusedLabel={null} hasChain={false} onClearFocus={() => {}} />
    )
    expect(getByText(/waiting for chain extraction/i)).toBeTruthy()
  })

  it('shows the no-logs state for a focused node without logs', () => {
    const { getByText } = render(
      <LogsPanel logs={[]} focusedLabel="powershell.exe" hasChain={true} onClearFocus={() => {}} />
    )
    expect(getByText(/no logs for this node/i)).toBeTruthy()
  })

  it('renders one row per log with timestamp and source', () => {
    const { container } = render(
      <LogsPanel
        logs={[row('evt-1', 1749100030, true), row('evt-2', 1749100060, true)]}
        focusedLabel={null}
        hasChain={true}
        onClearFocus={() => {}}
      />
    )
    expect(container.querySelectorAll('.logs-row').length).toBe(2)
    expect(container.textContent).toContain('sysmon')
  })

  it('marks on-chain rows with the chain accent class', () => {
    const { container } = render(
      <LogsPanel
        logs={[row('evt-1', 100, true), row('evt-2', 200, false)]}
        focusedLabel="powershell.exe"
        hasChain={true}
        onClearFocus={() => {}}
      />
    )
    expect(container.querySelectorAll('.logs-row-chain').length).toBe(1)
  })

  it('expands raw JSON on row click and collapses on second click', () => {
    const { container } = render(
      <LogsPanel logs={[row('evt-1', 100, true)]} focusedLabel={null} hasChain={true} onClearFocus={() => {}} />
    )
    const summary = container.querySelector('.logs-row-summary')!
    expect(container.querySelector('.logs-row-raw')).toBeNull()
    fireEvent.click(summary)
    expect(container.querySelector('.logs-row-raw')!.textContent).toContain('WS01')
    fireEvent.click(summary)
    expect(container.querySelector('.logs-row-raw')).toBeNull()
  })

  it('shows the focused title and fires onClearFocus from the clear button', () => {
    const onClearFocus = vi.fn()
    const { getByText } = render(
      <LogsPanel logs={[]} focusedLabel="powershell.exe" hasChain={true} onClearFocus={onClearFocus} />
    )
    expect(getByText('Logs: powershell.exe')).toBeTruthy()
    fireEvent.click(getByText(/clear filter/i))
    expect(onClearFocus).toHaveBeenCalledTimes(1)
  })

  it('shows the default title when unfocused', () => {
    const { getByText } = render(
      <LogsPanel logs={[]} focusedLabel={null} hasChain={false} onClearFocus={() => {}} />
    )
    expect(getByText('Related Logs')).toBeTruthy()
  })
})
