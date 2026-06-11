import { describe, it, expect, vi } from 'vitest'
import { render, fireEvent } from '@testing-library/react'
import { AttackPanel } from '../AttackPanel'
import type { ChainResultPayload, WsEdge } from '../ws'

const chain: ChainResultPayload = {
  confidence: 0.9,
  tactics: ['Initial Access', 'Credential Access'],
  steps: [
    { event_id: 'evt-1', description: 'winword spawned powershell', confidence: 0.7, ts: 1, technique_id: 'T1566.001', technique_name: 'Spearphishing Attachment', tactic: 'Initial Access' },
    { event_id: 'evt-2', description: 'powershell dumped lsass', confidence: 0.9, ts: 2, technique_id: 'T1003.001', technique_name: 'LSASS Memory', tactic: 'Credential Access' },
  ],
}

const edges: WsEdge[] = [
  { id: 'e1', src: 'a', dst: 'b', kind: 'spawned', ts: 1, confidence: 0.7, source_event_id: 'evt-1' },
  { id: 'e2', src: 'b', dst: 'c', kind: 'dumped_memory_of', ts: 2, confidence: 0.9, source_event_id: 'evt-2' },
]

describe('AttackPanel', () => {
  it('shows an empty state before any chain', () => {
    const { getByText } = render(<AttackPanel chain={null} edges={[]} onNodeFocus={() => {}} />)
    expect(getByText(/waiting for chain/i)).toBeTruthy()
  })

  it('renders one column per tactic in chain order with technique IDs', () => {
    const { container, getByText } = render(<AttackPanel chain={chain} edges={edges} onNodeFocus={() => {}} />)
    const cols = container.querySelectorAll('.attack-tactic')
    expect(cols.length).toBe(2)
    expect(cols[0].textContent).toContain('Initial Access')
    expect(cols[1].textContent).toContain('Credential Access')
    expect(getByText('T1003.001')).toBeTruthy()
  })

  it('focuses the destination node when a step is clicked', () => {
    const onNodeFocus = vi.fn()
    const { getByText } = render(<AttackPanel chain={chain} edges={edges} onNodeFocus={onNodeFocus} />)
    fireEvent.click(getByText('T1003.001'))
    expect(onNodeFocus).toHaveBeenCalledWith('c')
  })
})
