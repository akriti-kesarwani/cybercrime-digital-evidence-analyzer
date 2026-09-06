import { FileText, Printer, Shield, Hash, Clock, AlertTriangle, Flag } from 'lucide-react'
import type { Case, Evidence, EventRecord, Alert, Indicator } from '../../types'

interface Props {
  caseData: Case
  evidence: Evidence[]
  events: EventRecord[]
  alerts: Alert[]
  indicators: Indicator[]
}

export default function ReportPanel({ caseData, evidence, events, alerts, indicators }: Props) {
  function handlePrint() {
    window.print()
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between print:hidden">
        <h3 className="text-sm font-semibold text-soc-text">Investigation Report</h3>
        <button onClick={handlePrint} className="btn-primary text-sm flex items-center gap-2">
          <Printer className="w-4 h-4" /> Print / Save as PDF
        </button>
      </div>

      <div className="card p-8 max-w-4xl mx-auto bg-white text-gray-900 print:bg-white print:shadow-none print:border-0">
        {/* Header */}
        <div className="border-b-2 border-gray-300 pb-4 mb-6">
          <h1 className="text-2xl font-bold">Digital Forensics Investigation Report</h1>
          <p className="text-sm text-gray-600 mt-1 font-mono">{caseData.case_number}</p>
        </div>

        {/* Case Information */}
        <section className="mb-6">
          <h2 className="text-lg font-semibold mb-3 border-b border-gray-200 pb-1">1. Case Information</h2>
          <table className="w-full text-sm">
            <tbody>
              <tr><td className="py-1 font-medium text-gray-600 w-40">Case Name:</td><td>{caseData.name}</td></tr>
              <tr><td className="py-1 font-medium text-gray-600">Case Number:</td><td className="font-mono">{caseData.case_number}</td></tr>
              <tr><td className="py-1 font-medium text-gray-600">Status:</td><td>{caseData.status.replace('_', ' ')}</td></tr>
              <tr><td className="py-1 font-medium text-gray-600">Risk Level:</td><td>{caseData.risk_level || 'Not assessed'}</td></tr>
              <tr><td className="py-1 font-medium text-gray-600">Created:</td><td>{new Date(caseData.created_at).toLocaleString()}</td></tr>
              <tr><td className="py-1 font-medium text-gray-600">Last Updated:</td><td>{new Date(caseData.updated_at).toLocaleString()}</td></tr>
            </tbody>
          </table>
          {caseData.description && (
            <p className="text-sm mt-3 text-gray-700">{caseData.description}</p>
          )}
        </section>

        {/* Executive Summary */}
        <section className="mb-6">
          <h2 className="text-lg font-semibold mb-3 border-b border-gray-200 pb-1">2. Executive Summary</h2>
          <p className="text-sm text-gray-700 leading-relaxed">
            This case contains {evidence.length} evidence file(s), {events.length} normalized event(s),
            and {alerts.length} alert(s) were detected. {indicators.length} indicator(s) were extracted
            from the evidence. The current risk level is assessed as{' '}
            <strong>{caseData.risk_level || 'not yet assessed'}</strong>.
          </p>
        </section>

        {/* Evidence Inventory */}
        <section className="mb-6">
          <h2 className="text-lg font-semibold mb-3 border-b border-gray-200 pb-1">3. Evidence Inventory</h2>
          {evidence.length === 0 ? (
            <p className="text-sm text-gray-500">No evidence files.</p>
          ) : (
            <table className="w-full text-sm border border-gray-200">
              <thead className="bg-gray-100">
                <tr>
                  <th className="p-2 text-left">Filename</th>
                  <th className="p-2 text-left">Type</th>
                  <th className="p-2 text-left">Size</th>
                  <th className="p-2 text-left">SHA-256 Hash</th>
                  <th className="p-2 text-left">Integrity</th>
                </tr>
              </thead>
              <tbody>
                {evidence.map((ev) => (
                  <tr key={ev.id} className="border-t border-gray-200">
                    <td className="p-2 font-mono">{ev.filename}</td>
                    <td className="p-2">{ev.file_type}</td>
                    <td className="p-2">{(ev.file_size / 1024).toFixed(1)} KB</td>
                    <td className="p-2 font-mono text-xs">{ev.sha256_hash}</td>
                    <td className="p-2">{ev.integrity_status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>

        {/* Timeline Summary */}
        <section className="mb-6">
          <h2 className="text-lg font-semibold mb-3 border-b border-gray-200 pb-1">4. Timeline Summary</h2>
          {events.length === 0 ? (
            <p className="text-sm text-gray-500">No events recorded.</p>
          ) : (
            <table className="w-full text-sm border border-gray-200">
              <thead className="bg-gray-100">
                <tr>
                  <th className="p-2 text-left">Timestamp</th>
                  <th className="p-2 text-left">Event Type</th>
                  <th className="p-2 text-left">User</th>
                  <th className="p-2 text-left">Source IP</th>
                  <th className="p-2 text-left">Severity</th>
                </tr>
              </thead>
              <tbody>
                {events.slice(0, 50).map((ev) => (
                  <tr key={ev.id} className="border-t border-gray-200">
                    <td className="p-2 font-mono text-xs">{new Date(ev.timestamp).toLocaleString()}</td>
                    <td className="p-2">{ev.event_type.replace(/_/g, ' ')}</td>
                    <td className="p-2">{ev.username || '-'}</td>
                    <td className="p-2 font-mono">{ev.source_ip || '-'}</td>
                    <td className="p-2">{ev.severity}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {events.length > 50 && (
            <p className="text-xs text-gray-500 mt-2">
              Showing first 50 of {events.length} events.
            </p>
          )}
        </section>

        {/* Alerts */}
        <section className="mb-6">
          <h2 className="text-lg font-semibold mb-3 border-b border-gray-200 pb-1">5. Detected Alerts</h2>
          {alerts.length === 0 ? (
            <p className="text-sm text-gray-500">No alerts detected.</p>
          ) : (
            <div className="space-y-3">
              {alerts.map((a) => (
                <div key={a.id} className="border border-gray-200 rounded p-3">
                  <div className="flex items-center justify-between">
                    <strong className="text-sm">{a.alert_type}</strong>
                    <span className="text-xs px-2 py-0.5 rounded-full bg-gray-200">{a.severity}</span>
                  </div>
                  <p className="text-sm text-gray-600 mt-1">{a.reason}</p>
                  <p className="text-xs text-gray-500 mt-1">Rule: {a.detection_rule} | Confidence: {a.confidence}%</p>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* Indicators */}
        <section className="mb-6">
          <h2 className="text-lg font-semibold mb-3 border-b border-gray-200 pb-1">6. Indicators</h2>
          {indicators.length === 0 ? (
            <p className="text-sm text-gray-500">No indicators extracted.</p>
          ) : (
            <table className="w-full text-sm border border-gray-200">
              <thead className="bg-gray-100">
                <tr>
                  <th className="p-2 text-left">Type</th>
                  <th className="p-2 text-left">Value</th>
                  <th className="p-2 text-left">Occurrences</th>
                  <th className="p-2 text-left">Risk Score</th>
                </tr>
              </thead>
              <tbody>
                {indicators.map((ind) => (
                  <tr key={ind.id} className="border-t border-gray-200">
                    <td className="p-2">{ind.type}</td>
                    <td className="p-2 font-mono">{ind.value}</td>
                    <td className="p-2">{ind.occurrence_count}</td>
                    <td className="p-2">{ind.risk_score ?? '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>

        {/* Footer */}
        <section className="border-t-2 border-gray-300 pt-4 mt-8">
          <p className="text-xs text-gray-500">
            Report generated on {new Date().toLocaleString()} by the Cybercrime Digital Evidence Analyzer.
            This report is based on analysis of uploaded evidence files and should be reviewed by a qualified investigator.
          </p>
        </section>
      </div>
    </div>
  )
}
