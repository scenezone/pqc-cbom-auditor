import { X } from 'lucide-react'
import type { Finding } from '../types'
import RiskBadge from './RiskBadge'

export default function FindingDetailsPanel({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60">
      <aside className="h-full w-full max-w-xl overflow-y-auto border-l border-navy-700 bg-navy-900 p-6">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold">{finding.algorithm}</h2>
          <button onClick={onClose} aria-label="Close details"><X className="h-5 w-5" /></button>
        </div>
        <RiskBadge classification={finding.quantum_classification} />
        <dl className="mt-5 space-y-3 text-sm">
          <div><dt className="text-slate-400">Location</dt><dd>{finding.file_path}:{finding.start_line}</dd></div>
          <div><dt className="text-slate-400">Library</dt><dd>{finding.library_name}</dd></div>
          <div><dt className="text-slate-400">Operation</dt><dd>{finding.crypto_operation}</dd></div>
          <div><dt className="text-slate-400">Detection rule</dt><dd>{finding.detection_rule_id}</dd></div>
          <div><dt className="text-slate-400">Evidence</dt><dd><pre className="overflow-x-auto rounded bg-navy-800 p-3 text-xs">{finding.evidence_snippet}</pre></dd></div>
          <div><dt className="text-slate-400">Quantum-risk explanation</dt><dd>{finding.classification_reason}</dd></div>
          <div><dt className="text-slate-400">Reference</dt><dd>{finding.classification_reference}</dd></div>
          <div><dt className="text-slate-400">Recommended migration</dt><dd>{finding.migration_recommendation}</dd></div>
        </dl>
      </aside>
    </div>
  )
}
