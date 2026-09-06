import { useState, useMemo } from 'react'
import { Clock, Search } from 'lucide-react'
import type { EventRecord, Severity } from '../../types'

interface Props {
  events: EventRecord[]
}

const severityDot: Record<Severity, string> = {
  LOW: 'bg-severity-low',
  MEDIUM: 'bg-severity-medium',
  HIGH: 'bg-severity-high',
  CRITICAL: 'bg-severity-critical',
}

const eventTypeLabels: Record<string, string> = {
  LOGIN_FAILED: 'Failed Login',
  LOGIN_SUCCESS: 'Successful Login',
  LOGOUT: 'Logout',
  FILE_ACCESS: 'File Access',
  FILE_MODIFY: 'File Modified',
  FILE_DELETE: 'File Deleted',
  NETWORK_CONNECTION: 'Network Connection',
  NETWORK_DNS: 'DNS Query',
  NETWORK_BLOCKED: 'Network Blocked',
  PRIVILEGE_ESCALATION: 'Privilege Escalation',
  OTHER: 'Other',
}

export default function TimelinePanel({ events }: Props) {
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState<string>('ALL')
  const [typeFilter, setTypeFilter] = useState<string>('ALL')

  const filtered = useMemo(() => {
    return events.filter((ev) => {
      const matchesSearch =
        !search ||
        ev.username?.toLowerCase().includes(search.toLowerCase()) ||
        ev.source_ip?.toLowerCase().includes(search.toLowerCase()) ||
        ev.description?.toLowerCase().includes(search.toLowerCase()) ||
        ev.event_type.toLowerCase().includes(search.toLowerCase())
      const matchesSeverity = severityFilter === 'ALL' || ev.severity === severityFilter
      const matchesType = typeFilter === 'ALL' || ev.event_type === typeFilter
      return matchesSearch && matchesSeverity && matchesType
    })
  }, [events, search, severityFilter, typeFilter])

  const availableTypes = useMemo(() => {
    return Array.from(new Set(events.map((e) => e.event_type)))
  }, [events])

  if (events.length === 0) {
    return (
      <div className="card p-12 text-center">
        <Clock className="w-12 h-12 text-soc-muted mx-auto mb-3 opacity-50" />
        <p className="text-soc-muted">No events yet. Upload and parse evidence to build the timeline.</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="card p-4 flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-soc-muted" />
          <input
            type="text"
            placeholder="Search events..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="input-field pl-9"
          />
        </div>
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="input-field sm:w-40"
        >
          <option value="ALL">All Severities</option>
          <option value="LOW">Low</option>
          <option value="MEDIUM">Medium</option>
          <option value="HIGH">High</option>
          <option value="CRITICAL">Critical</option>
        </select>
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="input-field sm:w-44"
        >
          <option value="ALL">All Types</option>
          {availableTypes.map((t) => (
            <option key={t} value={t}>{eventTypeLabels[t] || t}</option>
          ))}
        </select>
      </div>

      {/* Timeline */}
      <div className="card p-5">
        <p className="text-xs text-soc-muted mb-4">
          Showing {filtered.length} of {events.length} events
        </p>
        <div className="relative">
          {/* Timeline line */}
          <div className="absolute left-4 top-0 bottom-0 w-px bg-soc-border"></div>

          <div className="space-y-3">
            {filtered.map((ev, idx) => (
              <div key={ev.id} className="relative flex gap-4 animate-fade-in" style={{ animationDelay: `${Math.min(idx * 20, 400)}ms` }}>
                {/* Dot */}
                <div className={`relative z-10 w-3 h-3 rounded-full mt-1.5 flex-shrink-0 ${severityDot[ev.severity]} ring-4 ring-soc-card`}></div>

                {/* Content */}
                <div className="flex-1 pb-3">
                  <div className="flex items-start justify-between gap-2 flex-wrap">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-medium text-soc-text">
                        {eventTypeLabels[ev.event_type] || ev.event_type}
                      </span>
                      <span className={`badge-${ev.severity.toLowerCase()}`}>{ev.severity}</span>
                    </div>
                    <span className="text-xs font-mono text-soc-muted">
                      {new Date(ev.timestamp).toLocaleString()}
                    </span>
                  </div>
                  <div className="flex items-center gap-4 mt-1.5 text-xs text-soc-muted flex-wrap">
                    {ev.username && <span>User: <span className="text-soc-text">{ev.username}</span></span>}
                    {ev.source_ip && <span>IP: <span className="text-soc-text font-mono">{ev.source_ip}</span></span>}
                    {ev.destination_ip && <span>Destination: <span className="text-soc-text font-mono">{ev.destination_ip}</span></span>}
                    {ev.source && <span>Source: <span className="text-soc-text">{ev.source}</span></span>}
                  </div>
                  {ev.raw_data && (
                    <div className="flex items-center gap-3 mt-1 text-xs text-soc-muted flex-wrap">
                      {typeof ev.raw_data.filename === 'string' && <span>File: <span className="text-soc-text">{ev.raw_data.filename}</span></span>}
                      {typeof ev.raw_data.path === 'string' && <span>Path: <span className="text-soc-text">{ev.raw_data.path}</span></span>}
                      {typeof ev.raw_data.action === 'string' && <span>Action: <span className="text-soc-text">{ev.raw_data.action}</span></span>}
                    </div>
                  )}
                  {ev.description && (
                    <p className="text-sm text-soc-muted mt-1">{ev.description}</p>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
