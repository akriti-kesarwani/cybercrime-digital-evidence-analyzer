import { Activity, TrendingUp, AlertTriangle, Network, Zap } from 'lucide-react'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts'
import type { Case, EventRecord, Alert, Evidence, Indicator, Severity } from '../../types'

interface Props {
  caseData: Case
  events: EventRecord[]
  alerts: Alert[]
  evidence: Evidence[]
  indicators: Indicator[]
}

const severityColors: Record<Severity, string> = {
  LOW: '#3b82f6',
  MEDIUM: '#f59e0b',
  HIGH: '#f97316',
  CRITICAL: '#ef4444',
}

export default function AnalysisPanel({ caseData, events, alerts, evidence, indicators }: Props) {
  // Event type distribution
  const typeCounts: Record<string, number> = {}
  events.forEach((e) => {
    typeCounts[e.event_type] = (typeCounts[e.event_type] || 0) + 1
  })
  const typeData = Object.entries(typeCounts)
    .map(([name, count]) => ({ name: name.replace(/_/g, ' '), count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8)

  // Top source IPs
  const ipCounts: Record<string, number> = {}
  events.forEach((e) => {
    if (e.source_ip) {
      ipCounts[e.source_ip] = (ipCounts[e.source_ip] || 0) + 1
    }
  })
  const topIps = Object.entries(ipCounts)
    .map(([ip, count]) => ({ ip, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5)

  // Severity distribution
  const sevCounts: Record<Severity, number> = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 }
  events.forEach((e) => { sevCounts[e.severity]++ })
  const sevData = (Object.entries(sevCounts) as [Severity, number][])
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }))

  // Alert type distribution
  const alertTypeCounts: Record<string, number> = {}
  alerts.forEach((a) => {
    alertTypeCounts[a.alert_type] = (alertTypeCounts[a.alert_type] || 0) + 1
  })
  const alertTypeData = Object.entries(alertTypeCounts)
    .map(([name, count]) => ({ name, count }))

  return (
    <div className="space-y-4">
      {/* Summary */}
      <div className="card p-5">
        <div className="flex items-center gap-3 mb-4">
          <Activity className="w-5 h-5 text-accent-cyan" />
          <h3 className="text-sm font-semibold text-soc-text">Analysis Summary</h3>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="p-3 rounded-md bg-soc-bg">
            <p className="text-xs text-soc-muted">Total Events</p>
            <p className="text-xl font-bold text-soc-text">{events.length}</p>
          </div>
          <div className="p-3 rounded-md bg-soc-bg">
            <p className="text-xs text-soc-muted">Total Alerts</p>
            <p className="text-xl font-bold text-soc-text">{alerts.length}</p>
          </div>
          <div className="p-3 rounded-md bg-soc-bg">
            <p className="text-xs text-soc-muted">Unique IPs</p>
            <p className="text-xl font-bold text-soc-text">{Object.keys(ipCounts).length}</p>
          </div>
          <div className="p-3 rounded-md bg-soc-bg">
            <p className="text-xs text-soc-muted">Indicators</p>
            <p className="text-xl font-bold text-soc-text">{indicators.length}</p>
          </div>
        </div>
      </div>

      {events.length === 0 ? (
        <div className="card p-12 text-center">
          <p className="text-soc-muted">
            No events to analyze yet. Upload and parse evidence to generate analysis.
          </p>
        </div>
      ) : (
        <>
          {/* Charts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Event type distribution */}
            <div className="card p-5">
              <div className="flex items-center gap-2 mb-4">
                <TrendingUp className="w-4 h-4 text-soc-muted" />
                <h3 className="text-sm font-semibold text-soc-text">Event Type Distribution</h3>
              </div>
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={typeData} layout="vertical">
                  <XAxis type="number" stroke="#8b9bb4" fontSize={11} axisLine={false} tickLine={false} />
                  <YAxis dataKey="name" type="category" stroke="#8b9bb4" fontSize={10} axisLine={false} tickLine={false} width={100} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#1a2332',
                      border: '1px solid #2a3a4e',
                      borderRadius: '8px',
                      fontSize: '12px',
                    }}
                  />
                  <Bar dataKey="count" fill="#06b6d4" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>

            {/* Severity distribution */}
            <div className="card p-5">
              <div className="flex items-center gap-2 mb-4">
                <AlertTriangle className="w-4 h-4 text-soc-muted" />
                <h3 className="text-sm font-semibold text-soc-text">Event Severity Distribution</h3>
              </div>
              {sevData.length > 0 ? (
                <ResponsiveContainer width="100%" height={220}>
                  <PieChart>
                    <Pie data={sevData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} innerRadius={40}>
                      {sevData.map((entry) => (
                        <Cell key={entry.name} fill={severityColors[entry.name as Severity]} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#1a2332',
                        border: '1px solid #2a3a4e',
                        borderRadius: '8px',
                        fontSize: '12px',
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-[220px] flex items-center justify-center text-sm text-soc-muted">No data</div>
              )}
            </div>
          </div>

          {/* Top source IPs */}
          {topIps.length > 0 && (
            <div className="card p-5">
              <div className="flex items-center gap-2 mb-4">
                <Network className="w-4 h-4 text-soc-muted" />
                <h3 className="text-sm font-semibold text-soc-text">Top Source IPs</h3>
              </div>
              <div className="space-y-2">
                {topIps.map((item, idx) => (
                  <div key={item.ip} className="flex items-center gap-3">
                    <span className="text-xs text-soc-muted w-4">{idx + 1}</span>
                    <span className="text-sm font-mono text-soc-text flex-1">{item.ip}</span>
                    <div className="flex-1 max-w-[200px] h-2 bg-soc-bg rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full bg-accent-cyan"
                        style={{ width: `${(item.count / topIps[0].count) * 100}%` }}
                      ></div>
                    </div>
                    <span className="text-xs text-soc-muted w-12 text-right">{item.count} events</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Alert types */}
          {alertTypeData.length > 0 && (
            <div className="card p-5">
              <div className="flex items-center gap-2 mb-4">
                <Zap className="w-4 h-4 text-soc-muted" />
                <h3 className="text-sm font-semibold text-soc-text">Detected Alert Types</h3>
              </div>
              <div className="space-y-2">
                {alertTypeData.map((item) => (
                  <div key={item.name} className="flex items-center justify-between p-3 rounded-md bg-soc-bg">
                    <span className="text-sm text-soc-text">{item.name}</span>
                    <span className="text-sm font-semibold text-soc-muted">{item.count}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}
