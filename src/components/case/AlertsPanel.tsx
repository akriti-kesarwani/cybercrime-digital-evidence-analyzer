import { useState } from 'react'
import { AlertTriangle, ChevronDown, ChevronUp } from 'lucide-react'
import type { Alert, EventRecord, Severity } from '../../types'

interface Props {
  alerts: Alert[]
  events: EventRecord[]
}

const severityColor: Record<Severity, string> = {
  LOW: 'text-severity-low',
  MEDIUM: 'text-severity-medium',
  HIGH: 'text-severity-high',
  CRITICAL: 'text-severity-critical',
}

export default function AlertsPanel({ alerts, events }: Props) {
  const [expandedId, setExpandedId] = useState<string | null>(null)

  if (alerts.length === 0) {
    return (
      <div className="card p-12 text-center">
        <AlertTriangle className="w-12 h-12 text-soc-muted mx-auto mb-3 opacity-50" />
        <p className="text-soc-muted">No alerts detected. Upload and analyze evidence to generate alerts.</p>
      </div>
    )
  }

  return (
    <div className="space-y-3">
      {alerts.map((alert) => {
        const isExpanded = expandedId === alert.id
        const relatedEvents = (alert.related_event_ids ?? [])
          .map((id) => events.find((e) => e.id === id))
          .filter(Boolean) as EventRecord[]

        return (
          <div key={alert.id} className="card overflow-hidden">
            <button
              onClick={() => setExpandedId(isExpanded ? null : alert.id)}
              className="w-full flex items-center justify-between p-4 hover:bg-soc-hover transition-colors text-left"
            >
              <div className="flex items-center gap-3 min-w-0">
                <AlertTriangle className={`w-5 h-5 flex-shrink-0 ${severityColor[alert.severity]}`} />
                <div className="min-w-0">
                  <p className="text-sm font-semibold text-soc-text truncate">{alert.alert_type}</p>
                  <p className="text-xs text-soc-muted truncate">
                    Rule: {alert.detection_rule} • Confidence: {alert.confidence}%
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-3 flex-shrink-0">
                <span className={`badge-${alert.severity.toLowerCase()}`}>{alert.severity}</span>
                {isExpanded ? <ChevronUp className="w-4 h-4 text-soc-muted" /> : <ChevronDown className="w-4 h-4 text-soc-muted" />}
              </div>
            </button>

            {isExpanded && (
              <div className="border-t border-soc-border p-4 space-y-3 animate-fade-in">
                <div>
                  <p className="text-xs text-soc-muted uppercase tracking-wider mb-1">Reason</p>
                  <p className="text-sm text-soc-text">{alert.reason}</p>
                </div>

                <div>
                  <p className="text-xs text-soc-muted uppercase tracking-wider mb-1">Detection Rule</p>
                  <p className="text-sm text-soc-text font-mono">{alert.detection_rule}</p>
                </div>

                <div>
                  <p className="text-xs text-soc-muted uppercase tracking-wider mb-1">Created</p>
                  <p className="text-sm text-soc-text">{new Date(alert.created_at).toLocaleString()}</p>
                </div>

                {relatedEvents.length > 0 && (
                  <div>
                    <p className="text-xs text-soc-muted uppercase tracking-wider mb-2">
                      Related Events ({relatedEvents.length})
                    </p>
                    <div className="space-y-1.5">
                      {relatedEvents.map((ev) => (
                        <div key={ev.id} className="flex items-center gap-3 p-2 rounded bg-soc-bg text-xs">
                          <span className="font-mono text-soc-muted">{new Date(ev.timestamp).toLocaleTimeString()}</span>
                          <span className="text-soc-text">{ev.event_type}</span>
                          {ev.username && <span className="text-soc-muted">{ev.username}</span>}
                          {ev.source_ip && <span className="text-soc-muted font-mono">{ev.source_ip}</span>}
                          <span className={`badge-${ev.severity.toLowerCase()} ml-auto`}>{ev.severity}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}
