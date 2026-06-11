// Pure selection logic for the Related Logs panel. Kept free of React so
// vitest can exercise every filtering branch directly.

import type { ChainResultPayload, LogEventPayload, WsEdge } from './ws'

export interface RelatedLog {
  log: LogEventPayload
  onChain: boolean
}

// Unfocused: logs backing the extracted chain's steps (the reconstruction's
// conclusion). Focused: logs backing any edge incident to the focused node,
// whether or not that edge made the chain. Always time-sorted ascending.
export function selectRelatedLogs(
  logs: Record<string, LogEventPayload>,
  edges: WsEdge[],
  chain: ChainResultPayload | null,
  focusedNodeId: string | null,
): RelatedLog[] {
  const chainIds = new Set(chain?.steps.map(s => s.event_id) ?? [])

  let ids: Set<string>
  if (focusedNodeId !== null) {
    ids = new Set()
    for (const e of edges) {
      if ((e.src === focusedNodeId || e.dst === focusedNodeId) && e.source_event_id) {
        ids.add(e.source_event_id)
      }
    }
  } else {
    ids = chainIds
  }

  const out: RelatedLog[] = []
  for (const id of ids) {
    const log = logs[id]
    if (log) out.push({ log, onChain: chainIds.has(id) })
  }
  out.sort((a, b) => a.log.ts - b.log.ts)
  return out
}

// nodeForEvent maps a chain step's event_id to the destination node of the edge
// it produced, so the ATT&CK ribbon can focus the right graph node on click.
export function nodeForEvent(edges: WsEdge[], eventId: string): string | null {
  for (const e of edges) {
    if (e.source_event_id === eventId) {
      return e.dst
    }
  }
  return null
}
