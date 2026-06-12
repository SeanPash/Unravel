import { useEffect, useMemo, useState } from 'react'
import type { WsEdge, ChainResultPayload, ChainStep } from './ws'
import { nodeForEvent } from './logFilter'
import {
  eventTimestamps,
  stepTs,
  tsToPercent,
  bestEdgeAt,
  buildPhases,
  phaseIndexAt,
  phaseColorAt,
  displayRange,
  PHASE_COLORS,
} from './timeline'

export interface TimeScrubberProps {
  minTs: number
  maxTs: number
  window: [number, number] | null
  onChange: (window: [number, number] | null) => void
  edges: WsEdge[]
  chain?: ChainResultPayload | null
  // Invoked with the graph node behind a selected event so the host can focus
  // it (which also filters the Logs tab to the underlying raw events). When a
  // chain step has no graph node, eventId carries its event for direct log
  // filtering instead.
  onEventFocus?: (nodeId: string | null, eventId?: string | null) => void
  // External request (e.g. a click on a log row) to select the event at ts.
  // seq increments per request so repeated jumps to the same ts re-fire.
  jump?: { ts: number; seq: number } | null
  // Tactic name of the selected attack phase card, so its timeline segment
  // answers with the same emphasis.
  activePhaseName?: string | null
}

const NEUTRAL_MARKER = '#6e7c8c'

function formatTs(ts: number): string {
  return new Date(ts * 1000).toISOString().slice(11, 19)
}

// Auto-advance dwell per event during playback (ms).
const PLAY_INTERVAL_MS = 1200

interface TickTooltip { ts: number; x: number; y: number }

export function TimeScrubber({ minTs, maxTs, window, onChange, edges, chain, onEventFocus, jump, activePhaseName }: TimeScrubberProps) {
  // The rail zooms to the active incident's span; events from other
  // incidents in the same feed fall outside and are not drawn. The incident
  // list is the navigation between incidents.
  const [dispMin, dispMax] = useMemo(
    () => displayRange(chain?.steps ?? [], minTs, maxTs),
    [chain, minTs, maxTs],
  )
  // Markers come from edge timestamps plus chain-step timestamps: a chain
  // step is an extracted attack event and must appear on the rail even when
  // no graph edge shares its ts (e.g. a privilege grant logged on the DC).
  const timestamps = useMemo(() => {
    const set = new Set(eventTimestamps(edges))
    for (const s of chain?.steps ?? []) set.add(s.ts)
    return [...set].filter(t => t >= dispMin && t <= dispMax).sort((a, b) => a - b)
  }, [edges, chain, dispMin, dispMax])
  const phases = useMemo(
    () => buildPhases(chain?.steps ?? [], chain?.tactics, dispMin, dispMax),
    [chain, dispMin, dispMax],
  )
  // Chain steps keyed by ts so markers and the detail strip can surface the
  // technique behind an event without rescanning the chain.
  const stepsByTs = useMemo(() => {
    const m = new Map<number, ChainStep>()
    for (const s of chain?.steps ?? []) if (!m.has(s.ts)) m.set(s.ts, s)
    return m
  }, [chain])

  const isLive = window === null
  const currentMax = window ? window[1] : maxTs
  // Scrub position clamped into the zoomed display range.
  const sliderVal = Math.min(Math.max(currentMax, dispMin), dispMax)
  const lastTs = timestamps.length > 0 ? timestamps[timestamps.length - 1] : dispMax
  const [playing, setPlaying] = useState(false)
  const [tickTooltip, setTickTooltip] = useState<TickTooltip | null>(null)
  const [selectedTs, setSelectedTs] = useState<number | null>(null)

  // Nothing to navigate if the range is a single instant or one event.
  const navDisabled = dispMin === dispMax || timestamps.length < 2
  const disabled = dispMin === dispMax

  function markerColor(ts: number): string {
    return phaseColorAt(phases, ts) ?? NEUTRAL_MARKER
  }

  // Leaving a specific event (transport controls, slider, Clear) drops the
  // selection and releases the log filter so the full log view returns.
  function clearSelection() {
    setSelectedTs(null)
    onEventFocus?.(null)
  }

  // Explicit deselection (Clear, re-clicking a marker, finishing a section
  // cycle) returns all the way to Live so the timeline and the logs read as
  // "back to everything" rather than stuck at the deselected moment.
  function deselectToLive() {
    clearSelection()
    onChange(null)
  }

  function handleSlider(e: React.ChangeEvent<HTMLInputElement>) {
    setPlaying(false)
    clearSelection()
    onChange([minTs, Number(e.target.value)])
  }

  function handleLive() {
    setPlaying(false)
    clearSelection()
    onChange(null)
  }

  function goPrev() {
    setPlaying(false)
    clearSelection()
    onChange([minTs, stepTs(timestamps, currentMax, 'prev')])
  }

  function goNext() {
    setPlaying(false)
    clearSelection()
    // At or past the latest visible event, re-enter Live rather than
    // dead-ending.
    if (timestamps.length === 0 || currentMax >= lastTs) onChange(null)
    else onChange([minTs, stepTs(timestamps, currentMax, 'next')])
  }

  function togglePlay() {
    if (!playing) {
      clearSelection()
      // Starting at or past the end of the rail (e.g. from Live) restarts
      // the playback from the beginning of the visible range.
      const base = window ? window[1] : maxTs
      if (timestamps.length > 0 && base >= dispMax) onChange([minTs, dispMin])
    }
    setPlaying(p => !p)
  }

  function selectEvent(ts: number) {
    setPlaying(false)
    setSelectedTs(ts)
    onChange([minTs, ts])
    if (onEventFocus) {
      // Prefer the edge produced by the chain step's source event; fall back
      // to the strongest edge sharing the timestamp. A chain step with no
      // edge at all is focused by its event id instead.
      const step = stepsByTs.get(ts)
      const viaStep = step ? nodeForEvent(edges, step.event_id) : null
      const e = bestEdgeAt(edges, ts)
      const node = viaStep ?? (e ? e.dst : null)
      if (node !== null) onEventFocus(node)
      else if (step) onEventFocus(null, step.event_id)
      else onEventFocus(null)
    }
  }

  // Timestamps of the markers a phase owns, matching the marker coloring.
  function phaseEventTs(phaseIdx: number): number[] {
    return timestamps.filter(t => phaseIndexAt(phases, t) === phaseIdx)
  }

  // Clicking a phase selects its first event; clicking again steps through
  // the events inside that phase. One more click past the last event returns
  // to Live with the full log view, before starting over.
  function selectPhase(phaseIdx: number) {
    const phaseTs = phaseEventTs(phaseIdx)
    if (phaseTs.length === 0) return
    const idx = selectedTs !== null ? phaseTs.indexOf(selectedTs) : -1
    if (idx === phaseTs.length - 1) deselectToLive()
    else selectEvent(phaseTs[idx + 1])
  }

  // External jump requests (log row clicks) select the event at the given
  // ts, same as clicking its marker, including the toggle: re-requesting the
  // already-selected event returns to Live. This is an imperative bridge:
  // the prop encodes a command, seq is its identity, and the handler
  // intentionally runs once per request rather than tracking other inputs.
  useEffect(() => {
    if (!jump) return
    // eslint-disable-next-line react-hooks/set-state-in-effect
    if (jump.ts === selectedTs) deselectToLive()
    else selectEvent(jump.ts)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [jump?.seq])

  // Playback auto-advances to the next event, takes one final step to the
  // end of the rail, and pauses there. The effect re-runs on `window` change
  // because each step depends on the current upper bound; clearInterval
  // covers both unmount and toggle-off.
  useEffect(() => {
    if (!playing) return
    const id = setInterval(() => {
      const base = window ? window[1] : maxTs
      const last = timestamps.length > 0 ? timestamps[timestamps.length - 1] : dispMax
      if (timestamps.length === 0 || base >= dispMax) {
        setPlaying(false)
        return
      }
      if (base >= last) {
        onChange([minTs, dispMax])
        setPlaying(false)
        return
      }
      onChange([minTs, stepTs(timestamps, base, 'next')])
    }, PLAY_INTERVAL_MS)
    return () => clearInterval(id)
  }, [playing, window, timestamps, minTs, maxTs, dispMax, onChange])

  const selectedStep = selectedTs !== null ? stepsByTs.get(selectedTs) : undefined
  const selectedEdge = selectedTs !== null ? bestEdgeAt(edges, selectedTs) : null
  const selectedPhaseIdx = selectedTs !== null ? phaseIndexAt(phases, selectedTs) : -1

  return (
    <div className="timeline">
      {tickTooltip && (
        <div
          className="timeline-tooltip"
          style={{ left: tickTooltip.x, top: tickTooltip.y - 6, transform: 'translate(-50%, -100%)' }}
        >
          <span className="timeline-tooltip-ts">{formatTs(tickTooltip.ts)}</span>
          <span className="timeline-tooltip-kind">
            {stepsByTs.get(tickTooltip.ts)?.technique_name
              ?? stepsByTs.get(tickTooltip.ts)?.description
              ?? bestEdgeAt(edges, tickTooltip.ts)?.kind
              ?? ''}
          </span>
        </div>
      )}

      <div className="timeline-phases">
        {phases.length > 0 ? (
          phases.map((p, i) => {
            // Segments share the markers' time coordinate system so each
            // chevron sits exactly over the events it owns.
            const leftPct = tsToPercent(p.startTs, dispMin, dispMax)
            const widthPct = tsToPercent(p.endTs, dispMin, dispMax) - leftPct
            const eventCount = phaseEventTs(i).length
            return (
              <button
                key={p.name}
                type="button"
                className={`timeline-phase${p.name === activePhaseName ? ' timeline-phase-active' : ''}`}
                style={{
                  left: `${leftPct}%`,
                  width: `${widthPct}%`,
                  '--phase-color': PHASE_COLORS[i % PHASE_COLORS.length],
                } as React.CSSProperties}
                title={eventCount > 1 ? `${p.name}: click to step through ${eventCount} events` : p.name}
                onClick={() => selectPhase(i)}
              >
                {widthPct >= 8 && <span className="timeline-phase-label">{p.name}</span>}
                {widthPct >= 8 && eventCount > 1 && (
                  <span className="timeline-phase-count">{eventCount}</span>
                )}
              </button>
            )
          })
        ) : (
          <div className="timeline-phase timeline-phase-empty">
            <span className="timeline-phase-label">Activity</span>
          </div>
        )}
      </div>

      <div className="timeline-track">
        <div className="timeline-rail" aria-hidden="true" />
        <div
          className="timeline-rail-progress"
          aria-hidden="true"
          style={{ width: `${tsToPercent(sliderVal, dispMin, dispMax)}%` }}
        />
        <input
          type="range"
          className="timeline-slider"
          min={dispMin}
          max={dispMax}
          value={sliderVal}
          onChange={handleSlider}
          disabled={disabled}
          aria-label="Time scrubber"
        />
        {timestamps.map((ts) => {
          const reached = ts <= currentMax
          const step = stepsByTs.get(ts)
          const classes = [
            'timeline-marker',
            reached ? 'reached' : '',
            step ? 'timeline-marker-chain' : '',
            selectedTs === ts ? 'selected' : '',
          ].filter(Boolean).join(' ')
          return (
            <button
              key={ts}
              type="button"
              className={classes}
              style={{
                left: `${tsToPercent(ts, dispMin, dispMax)}%`,
                '--marker-color': markerColor(ts),
              } as React.CSSProperties}
              aria-label={`Event at ${formatTs(ts)}`}
              onMouseEnter={(e) => {
                const r = (e.currentTarget as HTMLElement).getBoundingClientRect()
                setTickTooltip({ ts, x: r.left + r.width / 2, y: r.top })
              }}
              onMouseLeave={() => setTickTooltip(null)}
              onClick={() => { if (selectedTs === ts) deselectToLive(); else selectEvent(ts) }}
            />
          )
        })}
      </div>

      {selectedTs !== null && (
        <div className="timeline-detail">
          <span className="timeline-detail-ts">{formatTs(selectedTs)}</span>
          {selectedPhaseIdx >= 0 && (
            <span
              className="timeline-detail-phase"
              style={{ '--phase-color': PHASE_COLORS[selectedPhaseIdx % PHASE_COLORS.length] } as React.CSSProperties}
            >
              {phases[selectedPhaseIdx].name}
            </span>
          )}
          {selectedPhaseIdx >= 0 && phaseEventTs(selectedPhaseIdx).length > 1 && (
            <span className="timeline-detail-pos">
              {phaseEventTs(selectedPhaseIdx).indexOf(selectedTs) + 1}/{phaseEventTs(selectedPhaseIdx).length}
            </span>
          )}
          {selectedStep ? (
            <span className="timeline-detail-desc">
              {selectedStep.technique_id && (
                <span className="timeline-detail-technique">{selectedStep.technique_id}</span>
              )}
              {selectedStep.description}
            </span>
          ) : (
            <span className="timeline-detail-desc">
              {selectedEdge
                ? `${selectedEdge.kind}, confidence ${Math.round(selectedEdge.confidence * 100)}%`
                : 'No event detail available'}
            </span>
          )}
          <button
            type="button"
            className="timeline-detail-close"
            aria-label="Clear selection"
            onClick={deselectToLive}
          >
            Clear
          </button>
        </div>
      )}

      <div className="timeline-footer">
        <span className="timeline-label">{formatTs(dispMin)}</span>
        <div className="timeline-controls">
          <button
            className="timeline-btn"
            onClick={goPrev}
            disabled={navDisabled}
            aria-label="Previous event"
          >
            Prev
          </button>
          <button
            className="timeline-btn"
            onClick={togglePlay}
            disabled={navDisabled}
            aria-pressed={playing}
            aria-label={playing ? 'Pause' : 'Play'}
          >
            {playing ? 'Pause' : 'Play'}
          </button>
          <button
            className="timeline-btn"
            onClick={goNext}
            disabled={navDisabled}
            aria-label="Next event"
          >
            Next
          </button>
          <button
            className={`timeline-live-btn${isLive ? ' active' : ''}`}
            onClick={handleLive}
            aria-pressed={isLive}
          >
            Live
          </button>
        </div>
        <span className="timeline-label">{formatTs(dispMax)}</span>
      </div>
    </div>
  )
}
