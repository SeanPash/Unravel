import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { IncidentList } from '../IncidentList'
import type { IncidentState } from '../App'

function inc(partial: Partial<IncidentState> & { id: string }): IncidentState {
  return {
    id: partial.id,
    label: partial.label ?? partial.id,
    chain: partial.chain ?? {
      confidence: 0.8,
      steps: [{ event_id: 'e', description: 'd', confidence: 0.8, ts: 1 }],
    },
    narration: partial.narration ?? null,
    threatIntel: partial.threatIntel ?? null,
    firstSeen: partial.firstSeen ?? 0,
    awaitingNarration: partial.awaitingNarration ?? false,
    awaitingIntel: partial.awaitingIntel ?? false,
  }
}

describe('IncidentList', () => {
  it('shows an empty state when there are no incidents', () => {
    render(<IncidentList incidents={[]} activeIncidentId={null} onSelect={() => {}} />)
    expect(screen.getByText('No incidents yet')).toBeInTheDocument()
  })

  it('renders rows sorted by firstSeen with the active one marked', () => {
    const incidents = [
      inc({ id: 'inc-1', label: 'WS02', firstSeen: 300 }),
      inc({ id: 'inc-0', label: 'WS01', firstSeen: 100 }),
    ]
    render(<IncidentList incidents={incidents} activeIncidentId="inc-0" onSelect={() => {}} />)
    const options = screen.getAllByRole('option')
    expect(options[0]).toHaveTextContent('WS01') // earliest first
    expect(options[1]).toHaveTextContent('WS02')
    expect(options[0]).toHaveAttribute('aria-selected', 'true')
  })

  it('calls onSelect with the incident id when a row is clicked', () => {
    const onSelect = vi.fn()
    render(<IncidentList incidents={[inc({ id: 'inc-0', label: 'WS01' })]} activeIncidentId={null} onSelect={onSelect} />)
    fireEvent.click(screen.getByRole('option'))
    expect(onSelect).toHaveBeenCalledWith('inc-0')
  })
})
