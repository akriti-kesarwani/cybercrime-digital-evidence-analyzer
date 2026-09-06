import { useEffect, useState } from 'react'
import { Flag } from 'lucide-react'
import { supabase } from '../services/supabase'
import type { Indicator } from '../types'

export default function Indicators() {
  const [indicators, setIndicators] = useState<Indicator[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    async function fetchAll() {
      const { data, error: queryError } = await supabase.from('indicators').select('*').order('occurrence_count', { ascending: false })
      if (queryError) {
        setError(queryError.message)
        setLoading(false)
        return
      }
      setIndicators((data ?? []) as Indicator[])
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
        <h1 className="text-2xl font-bold text-soc-text">All Indicators</h1>
        <p className="text-sm text-soc-muted mt-1">Indicators of compromise across all cases</p>
      </div>

      {error && <div className="card p-4 text-sm text-severity-critical">Unable to load indicators: {error}</div>}

      {indicators.length === 0 ? (
        <div className="card p-12 text-center">
          <Flag className="w-12 h-12 text-soc-muted mx-auto mb-3 opacity-50" />
          <p className="text-soc-muted">No indicators extracted yet.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {indicators.map((ind) => (
            <div key={ind.id} className="card p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-soc-muted uppercase">{ind.type}</span>
                <span className="text-xs text-soc-muted">{ind.occurrence_count}x</span>
              </div>
              <p className="text-sm font-mono text-soc-text truncate">{ind.value}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
