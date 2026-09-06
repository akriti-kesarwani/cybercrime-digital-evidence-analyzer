import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  FolderKanban,
  FileSearch,
  Activity,
  Bell,
  TrendingUp,
  AlertTriangle,
  ChevronRight,
} from 'lucide-react'
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Area,
  AreaChart,
} from 'recharts'
import { supabase } from '../services/supabase'
import type { Case, Alert, Severity } from '../types'

const severityColors: Record<Severity, string> = {
  LOW: '#3b82f6',
  MEDIUM: '#f59e0b',
  HIGH: '#f97316',
  CRITICAL: '#ef4444',
}

interface Stats {
  totalCases: number
  totalEvidence: number
  totalEvents: number
  totalAlerts: number
  openCases: number
}

export default function Dashboard() {
  const [stats, setStats] = useState<Stats>({
    totalCases: 0,
    totalEvidence: 0,
    totalEvents: 0,
    totalAlerts: 0,
    openCases: 0,
  })
  const [recentCases, setRecentCases] = useState<Case[]>([])
  const [recentAlerts, setRecentAlerts] = useState<Alert[]>([])
  const [severityData, setSeverityData] = useState<{ name: string; value: number }[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    async function fetchDashboardData() {
      setLoading(true)

      const [casesRes, evidenceRes, eventsRes, alertsRes] = await Promise.all([
        supabase.from('cases').select('*'),
        supabase.from('evidence').select('id'),
        supabase.from('events').select('id'),
        supabase.from('alerts').select('*'),
      ])

      const cases = (casesRes.data ?? []) as Case[]
      const alerts = (alertsRes.data ?? []) as Alert[]

      setStats({
        totalCases: cases.length,
        totalEvidence: evidenceRes.data?.length ?? 0,
        totalEvents: eventsRes.data?.length ?? 0,
        totalAlerts: alerts.length,
        openCases: cases.filter((c) => c.status === 'OPEN' || c.status === 'UNDER_INVESTIGATION').length,
      })

      setRecentCases(
        [...cases]
          .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
          .slice(0, 5)
      )

      setRecentAlerts(
        [...alerts]
          .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
          .slice(0, 5)
      )

      // Severity distribution from alerts
      const sevCounts: Record<Severity, number> = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 }
      alerts.forEach((a) => { sevCounts[a.severity] = (sevCounts[a.severity] ?? 0) + 1 })
      setSeverityData(
        (Object.entries(sevCounts) as [Severity, number][])
          .filter(([, v]) => v > 0)
          .map(([name, value]) => ({ name, value }))
      )

      setLoading(false)
    }

    fetchDashboardData()
  }, [])

  const statCards = [
    { label: 'Total Cases', value: stats.totalCases, icon: FolderKanban, color: 'text-accent-blue' },
    { label: 'Evidence Files', value: stats.totalEvidence, icon: FileSearch, color: 'text-accent-cyan' },
    { label: 'Total Events', value: stats.totalEvents, icon: Activity, color: 'text-accent-green' },
    { label: 'Active Alerts', value: stats.totalAlerts, icon: Bell, color: 'text-severity-high' },
  ]

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="w-8 h-8 border-2 border-soc-border border-t-accent-cyan rounded-full animate-spin"></div>
      </div>
    )
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-soc-text">Investigation Dashboard</h1>
          <p className="text-sm text-soc-muted mt-1">
            Overview of active investigations and threat indicators
          </p>
        </div>
        <Link to="/cases/new" className="btn-primary text-sm">
          New Case
        </Link>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {statCards.map((card) => {
          const Icon = card.icon
          return (
            <div key={card.label} className="card p-5 hover:border-soc-hover transition-colors">
              <div className="flex items-start justify-between">
                <div>
                  <p className="text-xs text-soc-muted uppercase tracking-wider">{card.label}</p>
                  <p className="text-3xl font-bold text-soc-text mt-2">{card.value}</p>
                </div>
                <div className={`p-2.5 rounded-lg bg-soc-bg ${card.color}`}>
                  <Icon className="w-5 h-5" />
                </div>
              </div>
            </div>
          )
        })}
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Severity distribution */}
        <div className="card p-5">
          <h3 className="text-sm font-semibold text-soc-text mb-4">Alert Severity Distribution</h3>
          {severityData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={severityData}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  outerRadius={80}
                  innerRadius={40}
                  paddingAngle={2}
                >
                  {severityData.map((entry) => (
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
            <div className="h-[220px] flex items-center justify-center text-sm text-soc-muted">
              No alerts detected yet
            </div>
          )}
          {severityData.length > 0 && (
            <div className="flex justify-center gap-4 mt-2">
              {severityData.map((entry) => (
                <div key={entry.name} className="flex items-center gap-1.5">
                  <span
                    className="w-2.5 h-2.5 rounded-full"
                    style={{ backgroundColor: severityColors[entry.name as Severity] }}
                  ></span>
                  <span className="text-xs text-soc-muted">{entry.name}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Risk trend placeholder */}
        <div className="card p-5">
          <h3 className="text-sm font-semibold text-soc-text mb-4">Case Risk Levels</h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart
              data={[
                { level: 'LOW', count: recentCases.filter((c) => c.risk_level === 'LOW').length },
                { level: 'MEDIUM', count: recentCases.filter((c) => c.risk_level === 'MEDIUM').length },
                { level: 'HIGH', count: recentCases.filter((c) => c.risk_level === 'HIGH').length },
                { level: 'CRITICAL', count: recentCases.filter((c) => c.risk_level === 'CRITICAL').length },
              ]}
            >
              <XAxis dataKey="level" stroke="#8b9bb4" fontSize={11} axisLine={false} tickLine={false} />
              <YAxis stroke="#8b9bb4" fontSize={11} axisLine={false} tickLine={false} allowDecimals={false} />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#1a2332',
                  border: '1px solid #2a3a4e',
                  borderRadius: '8px',
                  fontSize: '12px',
                }}
              />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                <Cell fill="#3b82f6" />
                <Cell fill="#f59e0b" />
                <Cell fill="#f97316" />
                <Cell fill="#ef4444" />
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Recent cases and alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Recent cases */}
        <div className="card p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-soc-text">Recent Cases</h3>
            <Link to="/cases" className="text-xs text-accent-blue hover:underline flex items-center gap-1">
              View all <ChevronRight className="w-3 h-3" />
            </Link>
          </div>
          {recentCases.length > 0 ? (
            <div className="space-y-2">
              {recentCases.map((c) => (
                <Link
                  key={c.id}
                  to={`/cases/${c.id}`}
                  className="flex items-center justify-between p-3 rounded-md bg-soc-bg hover:bg-soc-hover transition-colors"
                >
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-soc-text truncate">{c.name}</p>
                    <p className="text-xs text-soc-muted">{c.case_number}</p>
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    {c.risk_level && (
                      <span className={`badge-${c.risk_level.toLowerCase()}`}>{c.risk_level}</span>
                    )}
                    <ChevronRight className="w-4 h-4 text-soc-muted" />
                  </div>
                </Link>
              ))}
            </div>
          ) : (
            <div className="text-center py-8">
              <FolderKanban className="w-8 h-8 text-soc-muted mx-auto mb-2 opacity-50" />
              <p className="text-sm text-soc-muted">No cases yet. Create one to get started.</p>
            </div>
          )}
        </div>

        {/* Recent alerts */}
        <div className="card p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-soc-text">Recent Alerts</h3>
            <Link to="/alerts" className="text-xs text-accent-blue hover:underline flex items-center gap-1">
              View all <ChevronRight className="w-3 h-3" />
            </Link>
          </div>
          {recentAlerts.length > 0 ? (
            <div className="space-y-2">
              {recentAlerts.map((a) => (
                <div
                  key={a.id}
                  className="flex items-center justify-between p-3 rounded-md bg-soc-bg hover:bg-soc-hover transition-colors"
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <AlertTriangle className={`w-4 h-4 flex-shrink-0`} style={{ color: severityColors[a.severity] }} />
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-soc-text truncate">{a.alert_type}</p>
                      <p className="text-xs text-soc-muted truncate">{a.detection_rule}</p>
                    </div>
                  </div>
                  <span className={`badge-${a.severity.toLowerCase()} flex-shrink-0`}>{a.severity}</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8">
              <Bell className="w-8 h-8 text-soc-muted mx-auto mb-2 opacity-50" />
              <p className="text-sm text-soc-muted">No alerts detected.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
