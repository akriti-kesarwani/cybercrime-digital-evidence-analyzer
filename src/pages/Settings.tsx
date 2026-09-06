import { Settings as SettingsIcon } from 'lucide-react'

export default function Settings() {
  return (
    <div className="space-y-6 animate-fade-in max-w-2xl">
      <div>
        <h1 className="text-2xl font-bold text-soc-text">Settings</h1>
        <p className="text-sm text-soc-muted mt-1">Application configuration</p>
      </div>

      <div className="card p-12 text-center">
        <SettingsIcon className="w-12 h-12 text-soc-muted mx-auto mb-3 opacity-50" />
        <p className="text-soc-muted">Settings will be available in a future phase.</p>
      </div>
    </div>
  )
}
