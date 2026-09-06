import { useEffect, useState } from 'react'
import { FileSearch } from 'lucide-react'
import { supabase } from '../services/supabase'
import type { Evidence } from '../types'

export default function EvidencePage() {
  const [evidence, setEvidence] = useState<Evidence[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    async function fetchAll() {
      const { data } = await supabase.from('evidence').select('*').order('uploaded_at', { ascending: false })
      setEvidence((data ?? []) as Evidence[])
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
        <h1 className="text-2xl font-bold text-soc-text">All Evidence</h1>
        <p className="text-sm text-soc-muted mt-1">Browse all uploaded evidence files across cases</p>
      </div>

      {evidence.length === 0 ? (
        <div className="card p-12 text-center">
          <FileSearch className="w-12 h-12 text-soc-muted mx-auto mb-3 opacity-50" />
          <p className="text-soc-muted">No evidence files uploaded yet.</p>
        </div>
      ) : (
        <div className="card p-5">
          <div className="space-y-2">
            {evidence.map((ev) => (
              <div key={ev.id} className="flex items-center gap-3 p-3 rounded-md bg-soc-bg hover:bg-soc-hover transition-colors">
                <FileSearch className="w-5 h-5 text-accent-cyan flex-shrink-0" />
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium text-soc-text truncate">{ev.filename}</p>
                  <p className="text-xs text-soc-muted">
                    {ev.file_type} • {(ev.file_size / 1024).toFixed(1)} KB • {ev.integrity_status}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
