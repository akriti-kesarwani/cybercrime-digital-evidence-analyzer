import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ArrowLeft, Save } from 'lucide-react'
import { Link } from 'react-router-dom'
import { supabase } from '../services/supabase'
import { useAuth } from '../context/AuthContext'
import { logAuditAction } from '../services/audit'
import type { CaseStatus, RiskLevel } from '../types'

export default function NewCase() {
  const navigate = useNavigate()
  const { user, profile } = useAuth()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [status, setStatus] = useState<CaseStatus>('OPEN')
  const [riskLevel, setRiskLevel] = useState<RiskLevel | ''>('')
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setSaving(true)

    if (!name.trim()) {
      setError('Case name is required.')
      setSaving(false)
      return
    }

    const { data, error: insertError } = await supabase
      .from('cases')
      .insert({
        name: name.trim(),
        description: description.trim() || null,
        status,
        risk_level: riskLevel || null,
        created_by: user?.id,
      })
      .select()
      .single()

    if (insertError) {
      setError(insertError.message)
      setSaving(false)
      return
    }

    await logAuditAction(user?.id ?? null, 'CASE_CREATED', 'cases', data.id, { case_number: data.case_number })
    navigate(`/cases/${data.id}`)
  }

  return (
    <div className="space-y-6 animate-fade-in max-w-2xl">
      <div className="flex items-center gap-4">
        <Link to="/cases" className="p-2 text-soc-muted hover:text-soc-text transition-colors">
          <ArrowLeft className="w-5 h-5" />
        </Link>
        <div>
          <h1 className="text-2xl font-bold text-soc-text">New Investigation Case</h1>
          <p className="text-sm text-soc-muted mt-1">Create a new digital forensics case</p>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="card p-6 space-y-5">
        <div>
          <label className="block text-sm font-medium text-soc-text mb-1.5">Case Name *</label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g., Suspicious Account Activity"
            className="input-field"
            required
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-soc-text mb-1.5">Description</label>
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Describe the incident and what triggered this investigation..."
            rows={4}
            className="input-field resize-none"
          />
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-soc-text mb-1.5">Status</label>
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value as CaseStatus)}
              className="input-field"
            >
              <option value="OPEN">Open</option>
              <option value="UNDER_INVESTIGATION">Under Investigation</option>
              <option value="CLOSED">Closed</option>
              <option value="ARCHIVED">Archived</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-soc-text mb-1.5">Risk Level</label>
            <select
              value={riskLevel}
              onChange={(e) => setRiskLevel(e.target.value as RiskLevel | '')}
              className="input-field"
            >
              <option value="">Not Assessed</option>
              <option value="LOW">Low</option>
              <option value="MEDIUM">Medium</option>
              <option value="HIGH">High</option>
              <option value="CRITICAL">Critical</option>
            </select>
          </div>
        </div>

        {error && (
          <div className="p-3 bg-severity-critical/10 border border-severity-critical/30 rounded-md">
            <p className="text-sm text-severity-critical">{error}</p>
          </div>
        )}

        <div className="flex justify-end gap-3 pt-2">
          <Link to="/cases" className="btn-secondary">Cancel</Link>
          <button type="submit" disabled={saving} className="btn-primary flex items-center gap-2 disabled:opacity-50">
            <Save className="w-4 h-4" />
            {saving ? 'Creating...' : 'Create Case'}
          </button>
        </div>
      </form>

      {profile && (
        <p className="text-xs text-soc-muted">
          Creating as <span className="text-soc-text">{profile.name}</span> ({profile.role}).
          This action will be recorded in the audit log.
        </p>
      )}
    </div>
  )
}
