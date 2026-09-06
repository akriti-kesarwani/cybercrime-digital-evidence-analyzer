import { useEffect, useState } from 'react'
import { Clock } from 'lucide-react'
import { supabase } from '../services/supabase'
import type { EventRecord } from '../types'

export default function Timeline() {
  const [events, setEvents] = useState<EventRecord[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    async function fetchAll() {
      const { data, error: queryError } = await supabase.from('events').select('*').order('timestamp', { ascending: false }).limit(100)
      if (queryError) {
        setError(queryError.message)
        setLoading(false)
        return
      }
      setEvents((data ?? []) as EventRecord[])
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
        <h1 className="text-2xl font-bold text-soc-text">Global Timeline</h1>
        <p className="text-sm text-soc-muted mt-1">Recent events across all cases (latest 100)</p>
      </div>

      {error && <div className="card p-4 text-sm text-severity-critical">Unable to load timeline: {error}</div>}

      {events.length === 0 ? (
        <div className="card p-12 text-center">
          <Clock className="w-12 h-12 text-soc-muted mx-auto mb-3 opacity-50" />
          <p className="text-soc-muted">No events recorded yet.</p>
        </div>
      ) : (
        <div className="card p-5">
          <div className="relative">
            <div className="absolute left-4 top-0 bottom-0 w-px bg-soc-border"></div>
            <div className="space-y-3">
              {events.map((ev) => (
                <div key={ev.id} className="relative flex gap-4">
                  <div className="w-3 h-3 rounded-full mt-1.5 flex-shrink-0 bg-accent-cyan ring-4 ring-soc-card"></div>
                  <div className="flex-1 pb-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium text-soc-text">{ev.event_type.replace(/_/g, ' ')}</span>
                      <span className="text-xs font-mono text-soc-muted">{new Date(ev.timestamp).toLocaleString()}</span>
                    </div>
                    {ev.username && <span className="text-xs text-soc-muted">User: {ev.username}</span>}
                    {ev.source_ip && <span className="text-xs text-soc-muted ml-2">IP: {ev.source_ip}</span>}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
