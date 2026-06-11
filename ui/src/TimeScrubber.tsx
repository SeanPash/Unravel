import { useEffect, useMemo, useState } from 'react'
import type { WsEdge } from './ws'
import { scoreToColor } from './GraphView'
import { eventTimestamps, stepTs, tsToPercent, maxConfidenceAt } from './timeline'

export interface TimeScrubberProps {
  minTs: number
  maxTs: number
  window: [number, number] | null
  onChange: (window: [number, number] | null) => void
  edges: WsEdge[]
}

function formatTs(ts: number): string {
  return new Date(ts * 1000).toISOString().slice(11, 19)
}

// Auto-advance dwell per event during playback (ms).
const PLAY_INTERVAL_MS = 1200

interface TickTooltip { ts: number; x: number; y: number }

export function TimeScrubber({ minTs, maxTs, window, onChange, edges }: TimeScrubberProps) {
  const timestamps = useMemo(() => eventTimestamps(edges), [edges])
  const isLive = window === null
  const currentMax = window ? window[1] : maxTs
  const [playing, setPlaying] = useState(false)
  const [tickTooltip, setTickTooltip] = useState<TickTooltip | null>(null)

  function getEdgeKindAt(ts: number): string {
    const found = edges.find(e => e.ts === ts)
    return found ? found.kind : ''
  }

  // Nothing to navigate if the range is a single instant or one event.
  const navDisabled = minTs === maxTs || timestamps.length < 2

  function handleSlider(e: React.ChangeEvent<HTMLInputElement>) {
    setPlaying(false)
    onChange([minTs, Number(e.target.value)])
  }

  function handleLive() {
    setPlaying(false)
    onChange(null)
  }

  function goPrev() {
    setPlaying(false)
    onChange([minTs, stepTs(timestamps, currentMax, 'prev')])
  }

  function goNext() {
    const next = stepTs(timestamps, currentMax, 'next')
    // At the latest event, re-enter Live rather than dead-ending.
    if (next === currentMax) onChange(null)
    else onChange([minTs, next])
  }

  // Playback auto-advances to the next event and pauses at the end. The effect
  // re-runs on `window` change because each step depends on the current upper
  // bound; clearInterval covers both unmount and toggle-off.
  useEffect(() => {
    if (!playing) return
    const id = setInterval(() => {
      const base = window ? window[1] : maxTs
      const next = stepTs(timestamps, base, 'next')
      if (next === base) {
        setPlaying(false)
        return
      }
      onChange([minTs, next])
    }, PLAY_INTERVAL_MS)
    return () => clearInterval(id)
  }, [playing, window, timestamps, minTs, maxTs, onChange])

  const disabled = minTs === maxTs

  return (
    <div className="time-scrubber">
      {tickTooltip && (
        <div
          className="scrubber-tick-tooltip"
          style={{ left: tickTooltip.x, top: tickTooltip.y - 6, transform: 'translate(-50%, -100%)' }}
        >
          <span className="scrubber-tick-tooltip-ts">{formatTs(tickTooltip.ts)}</span>
          <span className="scrubber-tick-tooltip-kind">{getEdgeKindAt(tickTooltip.ts)}</span>
        </div>
      )}
      <span className="scrubber-label">{formatTs(minTs)}</span>
      <div className="scrubber-track">
        <input
          type="range"
          className="scrubber-slider"
          min={minTs}
          max={maxTs}
          value={isLive ? maxTs : currentMax}
          onChange={handleSlider}
          disabled={disabled}
          aria-label="Time scrubber"
        />
        <div className="scrubber-ticks" aria-hidden="true">
          {timestamps.map(ts => {
            const reached = ts <= currentMax
            return (
              <span
                key={ts}
                className={`scrubber-tick${reached ? ' reached' : ''}`}
                style={{
                  left: `${tsToPercent(ts, minTs, maxTs)}%`,
                  ...(reached ? { background: scoreToColor(maxConfidenceAt(edges, ts)) } : {}),
                }}
                onMouseEnter={(e) => {
                  const r = (e.currentTarget as HTMLElement).getBoundingClientRect()
                  setTickTooltip({ ts, x: r.left + r.width / 2, y: r.top })
                }}
                onMouseLeave={() => setTickTooltip(null)}
                onClick={() => { setPlaying(false); onChange([minTs, ts]) }}
              />
            )
          })}
        </div>
      </div>
      <span className="scrubber-label">{formatTs(maxTs)}</span>
      <div className="scrubber-controls">
        <button
          className="scrubber-btn"
          onClick={goPrev}
          disabled={navDisabled}
          aria-label="Previous event"
        >
          Prev
        </button>
        <button
          className="scrubber-btn"
          onClick={() => setPlaying(p => !p)}
          disabled={navDisabled}
          aria-pressed={playing}
          aria-label={playing ? 'Pause' : 'Play'}
        >
          {playing ? 'Pause' : 'Play'}
        </button>
        <button
          className="scrubber-btn"
          onClick={goNext}
          disabled={navDisabled}
          aria-label="Next event"
        >
          Next
        </button>
        <button
          className={`scrubber-live-btn${isLive ? ' active' : ''}`}
          onClick={handleLive}
          aria-pressed={isLive}
        >
          Live
        </button>
      </div>
    </div>
  )
}
