export interface TimeScrubberProps {
  minTs: number
  maxTs: number
  window: [number, number] | null
  onChange: (window: [number, number] | null) => void
}

function formatTs(ts: number): string {
  return new Date(ts * 1000).toISOString().slice(11, 19)
}

export function TimeScrubber({ minTs, maxTs, window, onChange }: TimeScrubberProps) {
  const isLive = window === null
  const currentMax = window ? window[1] : maxTs

  function handleSlider(e: React.ChangeEvent<HTMLInputElement>) {
    const val = Number(e.target.value)
    onChange([minTs, val])
  }

  function handleLive() {
    onChange(null)
  }

  const disabled = minTs === maxTs

  return (
    <div className="time-scrubber">
      <span className="scrubber-label">{formatTs(minTs)}</span>
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
      <span className="scrubber-label">{formatTs(maxTs)}</span>
      <button
        className={`scrubber-live-btn${isLive ? ' active' : ''}`}
        onClick={handleLive}
        aria-pressed={isLive}
      >
        Live
      </button>
    </div>
  )
}
