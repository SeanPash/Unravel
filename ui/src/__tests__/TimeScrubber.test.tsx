import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, fireEvent, act } from '@testing-library/react'
import { TimeScrubber } from '../TimeScrubber'
import type { WsEdge } from '../ws'

// TimeScrubber imports scoreToColor from GraphView, which registers the cola
// extension at module scope. Mock cytoscape so the import needs no canvas.
vi.mock('cytoscape', () => {
  const factory = Object.assign(vi.fn(), { use: vi.fn() })
  return { default: factory }
})
vi.mock('cytoscape-cola', () => ({ default: vi.fn() }))

const edge = (id: string, ts: number, confidence = 0.5): WsEdge => ({
  id, src: 'a', dst: 'b', kind: 'spawned', ts, confidence,
})

const edges = [edge('e1', 100), edge('e2', 200), edge('e3', 300)]

afterEach(() => {
  vi.useRealTimers()
})

describe('TimeScrubber', () => {
  it('renders one tick per distinct event timestamp', () => {
    const { container } = render(
      <TimeScrubber minTs={100} maxTs={300} window={null} edges={edges} onChange={() => {}} />
    )
    expect(container.querySelectorAll('.timeline-marker').length).toBe(3)
  })

  it('advances to the next event timestamp on Next', () => {
    const onChange = vi.fn()
    const { getByLabelText } = render(
      <TimeScrubber minTs={100} maxTs={300} window={[100, 100]} edges={edges} onChange={onChange} />
    )
    fireEvent.click(getByLabelText('Next event'))
    expect(onChange).toHaveBeenCalledWith([100, 200])
  })

  it('re-enters Live when Next is pressed at the latest event', () => {
    const onChange = vi.fn()
    const { getByLabelText } = render(
      <TimeScrubber minTs={100} maxTs={300} window={null} edges={edges} onChange={onChange} />
    )
    fireEvent.click(getByLabelText('Next event'))
    expect(onChange).toHaveBeenCalledWith(null)
  })

  it('auto-advances while playing and clears the interval on unmount', () => {
    vi.useFakeTimers()
    const onChange = vi.fn()
    const { getByLabelText, unmount } = render(
      <TimeScrubber minTs={100} maxTs={300} window={[100, 100]} edges={edges} onChange={onChange} />
    )
    fireEvent.click(getByLabelText('Play'))
    act(() => { vi.advanceTimersByTime(1200) })
    expect(onChange).toHaveBeenCalledWith([100, 200])

    onChange.mockClear()
    unmount()
    act(() => { vi.advanceTimersByTime(1200) })
    expect(onChange).not.toHaveBeenCalled()
  })

  it('disables navigation when there are fewer than two events', () => {
    const { getByLabelText } = render(
      <TimeScrubber minTs={100} maxTs={100} window={null} edges={[edge('e1', 100)]} onChange={() => {}} />
    )
    expect((getByLabelText('Next event') as HTMLButtonElement).disabled).toBe(true)
    expect((getByLabelText('Play') as HTMLButtonElement).disabled).toBe(true)
  })
})
