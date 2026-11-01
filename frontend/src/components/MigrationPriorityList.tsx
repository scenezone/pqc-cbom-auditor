import type { Finding } from '../types'
import RiskBadge from './RiskBadge'

export default function MigrationPriorityList({ findings }: { findings: Finding[] }) {
  return (
    <div className="card">
      <h2 className="mb-4 font-semibold">Migration priority</h2>
      <div className="space-y-3">
        {findings.map((f, i) => (
          <div key={f.finding_id} className="rounded-lg border border-navy-700 p-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="font-medium">{i+1}. {f.algorithm} — {f.crypto_operation}</p>
              <RiskBadge classification={f.quantum_classification} />
            </div>
            <p className="mt-2 text-sm text-slate-400">{f.migration_recommendation}</p>
            <p className="mt-2 text-xs text-slate-500">{f.file_path}:{f.start_line} · Severity {f.severity_score}</p>
          </div>
        ))}
      </div>
    </div>
  )
}
