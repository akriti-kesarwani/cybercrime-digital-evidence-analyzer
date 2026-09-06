import { FileText } from 'lucide-react'

export default function Report() {
  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold text-soc-text">Reports</h1>
        <p className="text-sm text-soc-muted mt-1">Generate investigation reports from cases</p>
      </div>
      <div className="card p-12 text-center">
        <FileText className="w-12 h-12 text-soc-muted mx-auto mb-3 opacity-50" />
        <p className="text-soc-muted">
          Open a case and navigate to its Report tab to generate a report.
        </p>
      </div>
    </div>
  )
}
