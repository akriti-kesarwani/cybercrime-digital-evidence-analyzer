import { useState, useRef } from 'react'
import { Upload, FileText, Shield, Hash, Loader2, CheckCircle, AlertCircle } from 'lucide-react'
import { supabase } from '../../services/supabase'
import { useAuth } from '../../context/AuthContext'
import { logAuditAction } from '../../services/audit'
import { formatBytes, formatShortHash } from '../../utils/format'
import type { Evidence } from '../../types'

interface Props {
  evidence: Evidence[]
  caseId: string
  onUploaded?: () => void
}

const ALLOWED_TYPES = ['.txt', '.log', '.csv', '.json']
const MAX_SIZE = 10 * 1024 * 1024 // 10 MB

interface AnalysisStatus {
  [evidenceId: string]: {
    status: 'idle' | 'analyzing' | 'done' | 'error'
    message?: string
    events?: number
    alerts?: number
  }
}

export default function EvidencePanel({ evidence, caseId, onUploaded }: Props) {
  const { user, hasRole } = useAuth()
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [uploading, setUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const [analysisStatus, setAnalysisStatus] = useState<AnalysisStatus>({})

  const canUpload = hasRole('ADMIN', 'INVESTIGATOR')

  async function analyzeEvidence(evidenceId: string) {
    setAnalysisStatus((prev) => ({
      ...prev,
      [evidenceId]: { status: 'analyzing' },
    }))

    try {
      const supabaseUrl = import.meta.env.VITE_SUPABASE_URL
      const { data: sessionData } = await supabase.auth.getSession()
      const accessToken = sessionData.session?.access_token
      if (!accessToken) throw new Error('Your session has expired. Please sign in again.')

      const response = await fetch(`${supabaseUrl}/functions/v1/analyze-evidence`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer ' + accessToken,
          apikey: import.meta.env.VITE_SUPABASE_ANON_KEY,
        },
        body: JSON.stringify({ evidence_id: evidenceId, case_id: caseId }),
      })

      const result = await response.json()

      if (!response.ok) {
        throw new Error(result.error || 'Analysis failed')
      }

      setAnalysisStatus((prev) => ({
        ...prev,
        [evidenceId]: {
          status: 'done',
          events: result.events_extracted,
          alerts: result.alerts_generated,
          message: result.message,
        },
      }))

      onUploaded?.()
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Analysis failed'
      setAnalysisStatus((prev) => ({
        ...prev,
        [evidenceId]: { status: 'error', message: msg },
      }))
      onUploaded?.()
    }
  }

  async function handleUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return

    setError(null)

    const ext = '.' + file.name.split('.').pop()?.toLowerCase()
    if (!ALLOWED_TYPES.includes(ext)) {
      setError(`Unsupported file type: ${ext}. Allowed: ${ALLOWED_TYPES.join(', ')}`)
      return
    }

    if (file.size > MAX_SIZE) {
      setError(`File too large: ${(file.size / 1024 / 1024).toFixed(1)} MB. Max: 10 MB`)
      return
    }

    setUploading(true)
    setUploadProgress(5)
    let storagePath: string | null = null
    let storageUploaded = false
    let metadataInserted = false
    const evidenceId = crypto.randomUUID()

    try {
      const buffer = await file.arrayBuffer()
      const hashBuffer = await crypto.subtle.digest('SHA-256', buffer)
      setUploadProgress(25)
      const hashArray = Array.from(new Uint8Array(hashBuffer))
      const sha256 = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('')

      const safeName = file.name.replace(/[^a-zA-Z0-9._-]/g, '_')
      storagePath = `${caseId}/${evidenceId}_${safeName}`

      const { data: uploadData, error: uploadError } = await supabase.storage
        .from('evidence')
        .upload(storagePath, file)

      if (uploadError) throw uploadError
      if (!uploadData?.path) throw new Error('Storage upload did not return an object path')
      storageUploaded = true
      setUploadProgress(75)

      const { data: insertedEvidence, error: dbError } = await supabase
        .from('evidence')
        .insert({
          id: evidenceId,
          case_id: caseId,
          filename: safeName,
          original_filename: file.name,
          file_type: ext,
          file_size: file.size,
          sha256_hash: sha256,
          storage_path: uploadData.path,
          uploaded_by: user?.id,
          integrity_status: 'VERIFIED',
          parsed: false,
          analysis_status: 'PENDING',
        })
        .select()
        .single()

      if (dbError) throw dbError
      metadataInserted = true

      await logAuditAction(user?.id ?? null, 'EVIDENCE_UPLOADED', 'evidence', insertedEvidence.id, {
        case_id: caseId,
        filename: safeName,
        sha256: sha256.substring(0, 16) + '...',
      })

      onUploaded?.()

      // Automatically trigger analysis after upload
      await analyzeEvidence(insertedEvidence.id)
      setUploadProgress(100)
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Upload failed'
      if (storagePath && storageUploaded && !metadataInserted) {
        const { error: cleanupError } = await supabase.storage
          .from('evidence')
          .remove([storagePath])
        if (cleanupError) {
          console.error('Failed to remove orphaned evidence object:', cleanupError.message)
        }
      }
      if (metadataInserted) {
        await supabase
          .from('evidence')
          .update({ analysis_status: 'FAILED', analysis_error: msg })
          .eq('id', evidenceId)
      }
      setError(msg)
    } finally {
      setUploading(false)
      setUploadProgress(0)
      if (fileInputRef.current) fileInputRef.current.value = ''
    }
  }

  return (
    <div className="space-y-4">
      {canUpload && (
        <div className="card p-6">
          <h3 className="text-sm font-semibold text-soc-text mb-3">Upload Evidence</h3>
          <div
            onClick={() => fileInputRef.current?.click()}
            className="border-2 border-dashed border-soc-border rounded-lg p-8 text-center cursor-pointer hover:border-accent-blue/50 transition-colors"
          >
            <Upload className="w-8 h-8 text-soc-muted mx-auto mb-2" />
            <p className="text-sm text-soc-muted">
              {uploading ? `Uploading and analyzing... ${uploadProgress}%` : 'Click to select a file'}
            </p>
            <p className="text-xs text-soc-muted mt-1">
              Allowed: .txt, .log, .csv, .json (max 10 MB)
            </p>
            <input
              ref={fileInputRef}
              type="file"
              accept=".txt,.log,.csv,.json"
              onChange={handleUpload}
              className="hidden"
              disabled={uploading}
            />
          </div>
          {error && (
            <div className="mt-3 p-3 bg-severity-critical/10 border border-severity-critical/30 rounded-md">
              <p className="text-sm text-severity-critical">{error}</p>
            </div>
          )}
        </div>
      )}

      {/* Evidence list */}
      <div className="card p-5">
        <h3 className="text-sm font-semibold text-soc-text mb-4">
          Evidence Files ({evidence.length})
        </h3>
        {evidence.length === 0 ? (
          <p className="text-sm text-soc-muted text-center py-8">
            No evidence uploaded yet.
          </p>
        ) : (
          <div className="space-y-3">
            {evidence.map((ev) => {
              const status = analysisStatus[ev.id]
              const persistedStatus = ev.analysis_status ?? (ev.parsed ? 'COMPLETED' : 'PENDING')
              return (
                <div key={ev.id} className="p-3 rounded-md bg-soc-bg hover:bg-soc-hover transition-colors">
                  <div className="flex items-center gap-3">
                    <FileText className="w-5 h-5 text-accent-cyan flex-shrink-0" />
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-medium text-soc-text truncate">{ev.filename}</p>
                      <div className="flex items-center gap-3 mt-1 flex-wrap">
                        <span className="text-xs text-soc-muted">{ev.file_type}</span>
                        <span className="text-xs text-soc-muted">{formatBytes(ev.file_size)}</span>
                        <span className={`text-xs ${ev.integrity_status === 'VERIFIED' ? 'text-accent-green' : 'text-severity-critical'}`}>
                          <Shield className="w-3 h-3 inline mr-1" />
                          {ev.integrity_status}
                        </span>
                        {persistedStatus === 'COMPLETED' && (
                          <span className="text-xs text-accent-blue">Parsed</span>
                        )}
                        {persistedStatus === 'FAILED' && (
                          <span className="text-xs text-severity-critical">Analysis failed</span>
                        )}
                        {persistedStatus === 'PROCESSING' && (
                          <span className="text-xs text-accent-blue">Analysis in progress</span>
                        )}
                      </div>
                      <div className="flex items-center gap-1 mt-1">
                        <Hash className="w-3 h-3 text-soc-muted" />
                        <span className="text-xs font-mono text-soc-muted truncate">
                          {formatShortHash(ev.sha256_hash)}
                        </span>
                      </div>
                    </div>
                    {canUpload && !['COMPLETED', 'PROCESSING'].includes(persistedStatus) && !status && (
                      <button
                        onClick={() => analyzeEvidence(ev.id)}
                        className="btn-secondary text-xs whitespace-nowrap"
                      >
                        Analyze
                      </button>
                    )}
                    {status?.status === 'analyzing' && (
                      <div className="flex items-center gap-2 text-xs text-accent-blue">
                        <Loader2 className="w-4 h-4 animate-spin" />
                        Analyzing...
                      </div>
                    )}
                    {status?.status === 'done' && (
                      <div className="flex items-center gap-2 text-xs text-accent-green">
                        <CheckCircle className="w-4 h-4" />
                        {status.events ?? 0} events, {status.alerts ?? 0} alerts
                      </div>
                    )}
                    {status?.status === 'error' && (
                      <div className="flex items-center gap-2 text-xs text-severity-critical">
                        <AlertCircle className="w-4 h-4" />
                        {status.message}
                      </div>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}
