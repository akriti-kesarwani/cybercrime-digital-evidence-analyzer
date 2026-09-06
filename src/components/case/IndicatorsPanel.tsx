import { Flag, Globe, User, File, Hash, Link } from 'lucide-react'
import type { Indicator, IndicatorType } from '../../types'

interface Props {
  indicators: Indicator[]
}

const typeIcon: Record<IndicatorType, typeof Flag> = {
  IP: Globe,
  USERNAME: User,
  FILENAME: File,
  DOMAIN: Globe,
  URL: Link,
  HASH: Hash,
}

export default function IndicatorsPanel({ indicators }: Props) {
  if (indicators.length === 0) {
    return (
      <div className="card p-12 text-center">
        <Flag className="w-12 h-12 text-soc-muted mx-auto mb-3 opacity-50" />
        <p className="text-soc-muted">
          No indicators extracted yet. Indicators are generated when evidence is parsed and analyzed.
        </p>
      </div>
    )
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
      {indicators.map((ind) => {
        const Icon = typeIcon[ind.type] || Flag
        return (
          <div key={ind.id} className="card p-4 hover:border-soc-hover transition-colors">
            <div className="flex items-start gap-3">
              <div className="p-2 rounded-md bg-soc-bg text-accent-cyan">
                <Icon className="w-4 h-4" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-soc-muted uppercase tracking-wider">{ind.type}</span>
                  <span className="text-xs text-soc-muted">
                    {ind.occurrence_count} occurrence{ind.occurrence_count !== 1 ? 's' : ''}
                  </span>
                </div>
                <p className="text-sm font-mono text-soc-text mt-1 truncate">{ind.value}</p>
                {ind.description && (
                  <p className="text-xs text-soc-muted mt-1">{ind.description}</p>
                )}
                {ind.risk_score !== null && (
                  <div className="mt-2 flex items-center gap-2">
                    <div className="flex-1 h-1.5 bg-soc-bg rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full"
                        style={{
                          width: `${Math.min(ind.risk_score, 100)}%`,
                          backgroundColor: ind.risk_score >= 75 ? '#ef4444' : ind.risk_score >= 50 ? '#f97316' : ind.risk_score >= 25 ? '#f59e0b' : '#3b82f6',
                        }}
                      ></div>
                    </div>
                    <span className="text-xs text-soc-muted">{ind.risk_score}</span>
                  </div>
                )}
              </div>
            </div>
          </div>
        )
      })}
    </div>
  )
}
