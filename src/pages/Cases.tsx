import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { FolderKanban, Plus, Search, Filter } from 'lucide-react'
import { supabase } from '../services/supabase'
import type { Case, CaseStatus, RiskLevel } from '../types'

export default function Cases() {
  const [cases, setCases] = useState<Case[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('ALL')
  const [riskFilter, setRiskFilter] = useState<string>('ALL')

  useEffect(() => {
    async function fetchCases() {
      setLoading(true)
      const { data, error } = await supabase
        .from('cases')
        .select('*')
        .order('created_at', { ascending: false })

      if (error) {
        console.error('Error fetching cases:', error.message)
      } else {
        setCases((data ?? []) as Case[])
      }
      setLoading(false)
    }
    fetchCases()
  }, [])

  const filtered = cases.filter((c) => {
    const matchesSearch =
      c.name.toLowerCase().includes(search.toLowerCase()) ||
      c.case_number.toLowerCase().includes(search.toLowerCase())
    const matchesStatus = statusFilter === 'ALL' || c.status === statusFilter
    const matchesRisk = riskFilter === 'ALL' || c.risk_level === riskFilter
    return matchesSearch && matchesStatus && matchesRisk
  })

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-soc-text">Investigation Cases</h1>
          <p className="text-sm text-soc-muted mt-1">Manage and track all digital forensics cases</p>
        </div>
        <Link to="/cases/new" className="btn-primary text-sm flex items-center gap-2">
          <Plus className="w-4 h-4" /> New Case
        </Link>
      </div>

      {/* Filters */}
      <div className="card p-4 flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-soc-muted" />
          <input
            type="text"
            placeholder="Search by name or case number..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="input-field pl-9"
          />
        </div>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="input-field sm:w-48"
        >
          <option value="ALL">All Statuses</option>
          <option value="OPEN">Open</option>
          <option value="UNDER_INVESTIGATION">Under Investigation</option>
          <option value="CLOSED">Closed</option>
          <option value="ARCHIVED">Archived</option>
        </select>
        <select
          value={riskFilter}
          onChange={(e) => setRiskFilter(e.target.value)}
          className="input-field sm:w-48"
        >
          <option value="ALL">All Risk Levels</option>
          <option value="LOW">Low</option>
          <option value="MEDIUM">Medium</option>
          <option value="HIGH">High</option>
          <option value="CRITICAL">Critical</option>
        </select>
      </div>

      {/* Cases grid */}
      {loading ? (
        <div className="flex items-center justify-center h-64">
          <div className="w-8 h-8 border-2 border-soc-border border-t-accent-cyan rounded-full animate-spin"></div>
        </div>
      ) : filtered.length === 0 ? (
        <div className="card p-12 text-center">
          <FolderKanban className="w-12 h-12 text-soc-muted mx-auto mb-3 opacity-50" />
          <p className="text-soc-muted">No cases found. Create a new case to begin an investigation.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filtered.map((c) => (
            <Link
              key={c.id}
              to={`/cases/${c.id}`}
              className="card p-5 hover:border-accent-blue/50 transition-colors group"
            >
              <div className="flex items-start justify-between mb-3">
                <span className="text-xs font-mono text-soc-muted">{c.case_number}</span>
                {c.risk_level && (
                  <span className={`badge-${c.risk_level.toLowerCase()}`}>{c.risk_level}</span>
                )}
              </div>
              <h3 className="text-base font-semibold text-soc-text group-hover:text-accent-blue transition-colors mb-2">
                {c.name}
              </h3>
              <p className="text-sm text-soc-muted line-clamp-2 mb-4">
                {c.description || 'No description provided.'}
              </p>
              <div className="flex items-center justify-between text-xs text-soc-muted">
                <span className="badge bg-soc-bg text-soc-muted">{c.status.replace('_', ' ')}</span>
                <span>{new Date(c.created_at).toLocaleDateString()}</span>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  )
}
