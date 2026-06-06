import type { NarrationPayload } from './ws'

export interface NarrationPanelProps {
  narration: NarrationPayload | null
  awaitingNarration: boolean
}

export function NarrationPanel({ narration, awaitingNarration }: NarrationPanelProps) {
  if (awaitingNarration) {
    return (
      <div className="narration-panel">
        <div className="narration-spinner" aria-label="Awaiting narration" />
      </div>
    )
  }

  if (!narration) {
    return (
      <div className="narration-panel narration-empty">
        <p>Waiting for causal chain...</p>
      </div>
    )
  }

  return (
    <div className="narration-panel">
      <p className="narration-text">{narration.text}</p>
      {narration.hypotheses.length > 0 && (
        <>
          <h3>Missing evidence</h3>
          <ul className="narration-hypotheses">
            {narration.hypotheses.map((h, i) => <li key={i}>{h}</li>)}
          </ul>
        </>
      )}
      {narration.actions.length > 0 && (
        <>
          <h3>Containment actions</h3>
          <ol className="narration-actions">
            {narration.actions.map((a, i) => <li key={i}>{a}</li>)}
          </ol>
        </>
      )}
    </div>
  )
}
