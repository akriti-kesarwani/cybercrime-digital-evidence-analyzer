import { useEffect, useState } from 'react'
import { ScrollText } from 'lucide-react'
import { supabase } from '../services/supabase'
import type { AuditLog } from '../types'

export default function AuditLogs() {
  const [logs, setLogs] = useState<AuditLog[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    async function fetchLogs() {
      const { data } = await supabase
        .from('audit_logs')
        .select('*')
        .order('timestamp', { ascending: false })
        .limit(200)
      setLogs((data ?? []) as AuditLog[])
      setLoading(false)
    }
    fetchLogs()
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
        <h1 className="text-2xl font-bold text-soc-text">Audit Logs</h1>
        <p className="text-sm text-soc-muted mt-1">
          Complete record of all actions — this is part of the chain of custody
        </p>
      </div>

      {logs.length === 0 ? (
        <div className="card p-12 text-center">
          <ScrollText className="w-12 h-12 text-soc-muted mx-auto mb-3 opacity-50" />
          <p className="text-soc-muted">No audit entries recorded yet.</p>
        </div>
      ) : (
        <div className="card p-5">
          <div className="space-y-2">
            {logs.map((log) => (
              <div key={log.id} className="flex items-center gap-3 p-3 rounded-md bg-soc-bg hover:bg-soc-hover transition-colors">
                <div className="w-2 h-2 rounded-full bg-accent-cyan flex-shrink-0"></div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-3">
                    <span className="text-sm font-medium text-soc-text">{log.action}</span>
                    {log.resource && <span className="text-xs text-soc-muted">on {log.resource}</span>}
                  </div>
                  <div className="flex items-center gap-3 mt-0.5">
                    <span className="text-xs font-mono text-soc-muted">
                      {new Date(log.timestamp).toLocaleString()}
                    </span>
                    {log.user_id && (
                      <span className="text-xs text-soc-muted">User: {log.user_id.substring(0, 8)}...</span>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
