import { CaretDown } from '@phosphor-icons/react'
import { LogsPanel } from './LogsPanel'
import { AttackPanel } from './AttackPanel'
import { ThreatIntelPanel } from './ThreatIntelPanel'
import { InvestigationTracePanel } from './InvestigationTracePanel'
import type { RelatedLog } from './logFilter'
import type { TimelinePhase } from './timeline'
import type { ChainResultPayload, WsEdge, ThreatIntelPayload, LogEventPayload, AgentActivityPayload } from './ws'

export type DetailTab = 'trace' | 'logs' | 'attack' | 'intel'

export interface DetailTabsProps {
  activeTab: DetailTab
  onTabChange: (tab: DetailTab) => void
  // Logs
  logs: RelatedLog[]
  focusedLabel: string | null
  hasChain: boolean
  onClearFocus: () => void
  phases?: TimelinePhase[]
  onLogSelect?: (log: LogEventPayload) => void
  // ATT&CK
  chain: ChainResultPayload | null
  edges: WsEdge[]
  onNodeFocus: (nodeId: string | null) => void
  // Threat Intel
  intel: ThreatIntelPayload | null
  awaitingIntel: boolean
  // Investigation trace: live AI agent tool-use feed for the active incident.
  activity: AgentActivityPayload[]
  agentsBusy: boolean
  // MITRE technique navigation, shared by the ATT&CK and intel tabs.
  onTechniqueSelect?: (techniqueId: string) => void
  activeTechniqueId?: string | null
  chainTechniqueIds?: string[]
  // Collapse the whole detail panel down to its tab bar, the horizontal twin of
  // the columns' rail collapse.
  collapsed?: boolean
  onToggleCollapse?: () => void
}

const TABS: { id: DetailTab; label: string }[] = [
  { id: 'trace', label: 'Investigation' },
  { id: 'logs', label: 'Logs' },
  { id: 'attack', label: 'MITRE ATT&CK' },
  { id: 'intel', label: 'Threat Intel' },
]

export function DetailTabs(props: DetailTabsProps) {
  const { activeTab, onTabChange, collapsed = false, onToggleCollapse } = props
  return (
    <section className={`dash-panel detail-tabs${collapsed ? ' detail-tabs-collapsed' : ''}`}>
      <div className="detail-tabs-header" role="tablist">
        {TABS.map((t) => (
          <button
            key={t.id}
            role="tab"
            type="button"
            aria-selected={activeTab === t.id}
            className={`detail-tab${activeTab === t.id ? ' detail-tab-active' : ''}`}
            onClick={() => onTabChange(t.id)}
          >
            {t.label}
          </button>
        ))}
        {onToggleCollapse && (
          <button
            type="button"
            className="detail-tabs-toggle"
            aria-expanded={!collapsed}
            onClick={onToggleCollapse}
            title={collapsed ? 'Expand the detail panel' : 'Collapse the detail panel'}
          >
            <span className="dash-panel-caret" aria-hidden="true">
              <CaretDown size={12} weight="bold" />
            </span>
          </button>
        )}
      </div>
      <div className="dash-panel-body detail-tabs-body">
        {activeTab === 'trace' && (
          <InvestigationTracePanel
            activity={props.activity}
            busy={props.agentsBusy}
            hasChain={props.hasChain}
          />
        )}
        {activeTab === 'logs' && (
          <LogsPanel
            logs={props.logs}
            focusedLabel={props.focusedLabel}
            hasChain={props.hasChain}
            onClearFocus={props.onClearFocus}
            phases={props.phases}
            onLogSelect={props.onLogSelect}
          />
        )}
        {activeTab === 'attack' && (
          <AttackPanel
            chain={props.chain}
            edges={props.edges}
            onNodeFocus={props.onNodeFocus}
            onTechniqueSelect={props.onTechniqueSelect}
            activeTechniqueId={props.activeTechniqueId}
          />
        )}
        {activeTab === 'intel' && (
          <ThreatIntelPanel
            intel={props.intel}
            awaiting={props.awaitingIntel}
            hasChain={props.hasChain}
            onTechniqueSelect={props.onTechniqueSelect}
            activeTechniqueId={props.activeTechniqueId}
            chainTechniqueIds={props.chainTechniqueIds}
          />
        )}
      </div>
    </section>
  )
}
