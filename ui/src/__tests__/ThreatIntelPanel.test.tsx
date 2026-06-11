import { describe, it, expect } from 'vitest'
import { render } from '@testing-library/react'
import { ThreatIntelPanel } from '../ThreatIntelPanel'
import type { ThreatIntelPayload } from '../ws'

const intel: ThreatIntelPayload = {
  status: 'ok',
  summary: 'Reset krbtgt twice.',
  techniques: [
    { id: 'T1003.001', name: 'LSASS Memory', groups: ['APT29'], software: ['Mimikatz'], mitigations: ['Enable LSA Protection'] },
  ],
  cve_matches: [{ id: 'CVE-2020-1472', summary: 'Zerologon', in_kev: true, severity: 'CRITICAL' }],
}

describe('ThreatIntelPanel', () => {
  it('shows the waiting state before any chain', () => {
    const { getByText } = render(<ThreatIntelPanel intel={null} awaiting={false} hasChain={false} />)
    expect(getByText(/waiting for chain/i)).toBeTruthy()
  })

  it('shows a spinner while awaiting', () => {
    const { container } = render(<ThreatIntelPanel intel={null} awaiting={true} hasChain={true} />)
    expect(container.querySelector('.intel-spinner')).toBeTruthy()
  })

  it('renders summary, technique cards, and CVE matches', () => {
    const { getByText, container } = render(<ThreatIntelPanel intel={intel} awaiting={false} hasChain={true} />)
    expect(getByText('Reset krbtgt twice.')).toBeTruthy()
    expect(getByText('Mimikatz')).toBeTruthy()
    expect(getByText('APT29')).toBeTruthy()
    expect(getByText(/CVE-2020-1472/)).toBeTruthy()
    expect(container.querySelectorAll('.intel-technique').length).toBe(1)
  })

  it('shows an error notice when status is error', () => {
    const { getByText } = render(
      <ThreatIntelPanel intel={{ status: 'error', summary: 'failed', techniques: [] }} awaiting={false} hasChain={true} />
    )
    expect(getByText(/failed/i)).toBeTruthy()
  })
})
