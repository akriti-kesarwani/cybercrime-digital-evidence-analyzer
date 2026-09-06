import { useEffect, useState } from 'react'
import { useParams, Link, NavLink, Route, Routes } from 'react-router-dom'
import {
  ArrowLeft,
  FolderKanban,
  FileSearch,
  Clock,
  Bell,
  Flag,
  Activity,
  FileText,
  Shield,
} from 'lucide-react'
import { supabase } from '../services/supabase'
import type { Case, Evidence, EventRecord, Alert, Indicator } from '../types'
import EvidencePanel from '../components/case/EvidencePanel'
import TimelinePanel from '../components/case/TimelinePanel'
import AlertsPanel from '../components/case/AlertsPanel'
import IndicatorsPanel from '../components/case/IndicatorsPanel'
import AnalysisPanel from '../components/case/AnalysisPanel'
import ReportPanel from '../components/case/ReportPanel'

export default function CaseDetail() {
  const { id } = useParams<{ id: string }>()
  const [caseData, setCaseData] = useState<Case | null>(null)
  const [evidence, setEvidence] = useState<Evidence[]>([])
  const [events, setEvents] = useState<EventRecord[]>([])
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [indicators, setIndicators] = useState<Indicator[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  async function refreshCaseData() {
    if (!id) return
    setError(null)
    const [caseRes, evidenceRes, eventsRes, alertsRes, indicatorsRes] = await Promise.all([
      supabase.from('cases').select('*').eq('id', id).maybeSingle(),
      supabase.from('evidence').select('*').eq('case_id', id).order('uploaded_at', { ascending: false }),
      supabase.from('events').select('*').eq('case_id', id).order('timestamp', { ascending: true }),
      supabase.from('alerts').select('*').eq('case_id', id).order('created_at', { ascending: false }),
      supabase.from('indicators').select('*').eq('case_id', id).order('occurrence_count', { ascending: false }),
    ])

    const queryError = caseRes.error ?? evidenceRes.error ?? eventsRes.error ?? alertsRes.error ?? indicatorsRes.error
    if (queryError) {
      setError(queryError.message)
      return
    }
    if (caseRes.data) setCaseData(caseRes.data as Case)
    setEvidence((evidenceRes.data ?? []) as Evidence[])
    setEvents((eventsRes.data ?? []) as EventRecord[])
    setAlerts((alertsRes.data ?? []) as Alert[])
    setIndicators((indicatorsRes.data ?? []) as Indicator[])
  }

  useEffect(() => {
    if (!id) return
    async function fetchCase() {
      setLoading(true)
      await refreshCaseData()
      setLoading(false)
    }
    fetchCase()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id])

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="w-8 h-8 border-2 border-soc-border border-t-accent-cyan rounded-full animate-spin"></div>
      </div>
    )
  }

  if (!caseData) {
    if (error) {
      return (
        <div className="card p-6 text-sm text-severity-critical">
          Unable to load this case: {error}
        </div>
      )
    }
    return (
      <div className="text-center py-20">
        <p className="text-lg text-soc-muted">Case not found.</p>
        <Link to="/cases" className="text-accent-blue hover:underline mt-2 inline-block">
          Back to cases
        </Link>
      </div>
    )
  }

  const tabs = [
    { to: '', label: 'Overview', icon: FolderKanban, end: true },
    { to: 'evidence', label: 'Evidence', icon: FileSearch, count: evidence.length },
    { to: 'timeline', label: 'Timeline', icon: Clock, count: events.length },
    { to: 'alerts', label: 'Alerts', icon: Bell, count: alerts.length },
    { to: 'indicators', label: 'Indicators', icon: Flag, count: indicators.length },
    { to: 'analysis', label: 'Analysis', icon: Activity },
    { to: 'report', label: 'Report', icon: FileText },
  ]

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Breadcrumb */}
      <div className="flex items-center gap-3">
        <Link to="/cases" className="p-2 text-soc-muted hover:text-soc-text transition-colors">
          <ArrowLeft className="w-5 h-5" />
        </Link>
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-soc-text">{caseData.name}</h1>
            {caseData.risk_level && (
              <span className={`badge-${caseData.risk_level.toLowerCase()}`}>{caseData.risk_level}</span>
            )}
          </div>
          <p className="text-sm text-soc-muted mt-0.5 font-mono">{caseData.case_number}</p>
        </div>
      </div>

      {/* Quick stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: 'Evidence', value: evidence.length, icon: FileSearch },
          { label: 'Events', value: events.length, icon: Activity },
          { label: 'Alerts', value: alerts.length, icon: Bell },
          { label: 'Indicators', value: indicators.length, icon: Flag },
        ].map((s) => {
          const Icon = s.icon
          return (
            <div key={s.label} className="card p-4">
              <div className="flex items-center gap-3">
                <Icon className="w-5 h-5 text-soc-muted" />
                <div>
                  <p className="text-2xl font-bold text-soc-text">{s.value}</p>
                  <p className="text-xs text-soc-muted">{s.label}</p>
                </div>
              </div>
            </div>
          )
        })}
      </div>

      {/* Tabs */}
      <div className="border-b border-soc-border flex gap-1 overflow-x-auto">
        {tabs.map((tab) => {
          const Icon = tab.icon
          return (
            <NavLink
              key={tab.to}
              to={tab.to}
              end={tab.end}
              className={({ isActive }) =>
                `flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${
                  isActive
                    ? 'border-accent-blue text-accent-blue'
                    : 'border-transparent text-soc-muted hover:text-soc-text'
                }`
              }
            >
              <Icon className="w-4 h-4" />
              {tab.label}
              {tab.count !== undefined && tab.count > 0 && (
                <span className="text-xs bg-soc-hover px-1.5 py-0.5 rounded">{tab.count}</span>
              )}
            </NavLink>
          )
        })}
      </div>

      {/* Tab content */}
      <Routes>
        <Route
          index
          element={
            <div className="card p-6 space-y-4">
              <div className="flex items-center gap-3 mb-4">
                <Shield className="w-5 h-5 text-accent-cyan" />
                <h2 className="text-lg font-semibold text-soc-text">Case Overview</h2>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <p className="text-xs text-soc-muted uppercase tracking-wider mb-1">Status</p>
                  <p className="text-soc-text">{caseData.status.replace('_', ' ')}</p>
                </div>
                <div>
                  <p className="text-xs text-soc-muted uppercase tracking-wider mb-1">Risk Level</p>
                  <p className="text-soc-text">{caseData.risk_level || 'Not assessed'}</p>
                </div>
                <div>
                  <p className="text-xs text-soc-muted uppercase tracking-wider mb-1">Created</p>
                  <p className="text-soc-text">{new Date(caseData.created_at).toLocaleString()}</p>
                </div>
                <div>
                  <p className="text-xs text-soc-muted uppercase tracking-wider mb-1">Last Updated</p>
                  <p className="text-soc-text">{new Date(caseData.updated_at).toLocaleString()}</p>
                </div>
              </div>
              {caseData.description && (
                <div className="pt-4 border-t border-soc-border">
                  <p className="text-xs text-soc-muted uppercase tracking-wider mb-2">Description</p>
                  <p className="text-sm text-soc-text leading-relaxed">{caseData.description}</p>
                </div>
              )}
            </div>
          }
        />
        <Route path="evidence" element={<EvidencePanel evidence={evidence} caseId={caseData.id} onUploaded={refreshCaseData} />} />
        <Route path="timeline" element={<TimelinePanel events={events} />} />
        <Route path="alerts" element={<AlertsPanel alerts={alerts} events={events} />} />
        <Route path="indicators" element={<IndicatorsPanel indicators={indicators} />} />
        <Route path="analysis" element={<AnalysisPanel caseData={caseData} events={events} alerts={alerts} evidence={evidence} indicators={indicators} />} />
        <Route path="report" element={<ReportPanel caseData={caseData} evidence={evidence} events={events} alerts={alerts} indicators={indicators} />} />
      </Routes>
    </div>
  )
}
