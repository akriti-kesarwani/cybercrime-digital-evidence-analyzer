import { useEffect, useState } from 'react'
import { Bell } from 'lucide-react'
import { supabase } from '../services/supabase'
import type { Alert } from '../types'

export default function Alerts() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    async function fetchAll() {
      const { data, error: queryError } = await supabase.from('alerts').select('*').order('created_at', { ascending: false })
      if (queryError) {
        setError(queryError.message)
        setLoading(false)
        return
      }
      setAlerts((data ?? []) as Alert[])
      setLoading(false)
    }
    fetchAll()
  }, [])

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="w-8 h-8 border-2 border-soc-border border-t-accent-cyan rounded-full animate-spin"></div>
      </div>
    )
  }

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold text-soc-text">All Alerts</h1>
        <p className="text-sm text-soc-muted mt-1">All detected alerts across cases</p>
      </div>

      {error && <div className="card p-4 text-sm text-severity-critical">Unable to load alerts: {error}</div>}

      {alerts.length === 0 ? (
        <div className="card p-12 text-center">
          <Bell className="w-12 h-12 text-soc-muted mx-auto mb-3 opacity-50" />
          <p className="text-soc-muted">No alerts detected.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {alerts.map((a) => (
            <div key={a.id} className="card p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-semibold text-soc-text">{a.alert_type}</p>
                  <p className="text-xs text-soc-muted mt-1">{a.reason}</p>
                  <p className="text-xs text-soc-muted mt-1">Rule: {a.detection_rule} • Confidence: {a.confidence}%</p>
                </div>
                <span className={`badge-${a.severity.toLowerCase()}`}>{a.severity}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
