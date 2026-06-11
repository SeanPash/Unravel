import { describe, it, expect, vi } from 'vitest'
import { render, fireEvent } from '@testing-library/react'
import { DetailTabs } from '../DetailTabs'

const baseProps = {
  activeTab: 'logs' as const,
  onTabChange: () => {},
  // Logs
  logs: [],
  focusedLabel: null,
  hasChain: false,
  onClearFocus: () => {},
  // ATT&CK
  chain: null,
  edges: [],
  onNodeFocus: () => {},
  // Intel
  intel: null,
  awaitingIntel: false,
}

describe('DetailTabs', () => {
  it('renders three tab buttons', () => {
    const { getByRole } = render(<DetailTabs {...baseProps} />)
    expect(getByRole('tab', { name: /logs/i })).toBeTruthy()
    expect(getByRole('tab', { name: /att&ck/i })).toBeTruthy()
    expect(getByRole('tab', { name: /threat intel/i })).toBeTruthy()
  })

  it('shows the Logs panel by default', () => {
    const { container } = render(<DetailTabs {...baseProps} />)
    expect(container.querySelector('.logs-pane')).toBeTruthy()
  })

  it('calls onTabChange when a tab is clicked', () => {
    const onTabChange = vi.fn()
    const { getByRole } = render(<DetailTabs {...baseProps} onTabChange={onTabChange} />)
    fireEvent.click(getByRole('tab', { name: /att&ck/i }))
    expect(onTabChange).toHaveBeenCalledWith('attack')
  })

  it('renders the ATT&CK panel when activeTab is attack', () => {
    const { container } = render(<DetailTabs {...baseProps} activeTab="attack" />)
    expect(container.querySelector('.attack-empty')).toBeTruthy()
  })
})
