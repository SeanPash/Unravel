import type { WsNode, WsEdge, ChainResultPayload } from './ws'

export interface GraphViewProps {
  nodes: WsNode[]
  edges: WsEdge[]
  chain: ChainResultPayload | null
  timeWindow?: [number, number] | null
}

export function GraphView({ nodes, edges }: GraphViewProps) {
  return (
    <div className="graph-view-placeholder">
      <p>Graph canvas - coming in section 5</p>
      <p>{nodes.length} nodes / {edges.length} edges</p>
    </div>
  )
}
