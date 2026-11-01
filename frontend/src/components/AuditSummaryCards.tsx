import type { ScanSummary } from '../types'
export default function AuditSummaryCards({ summary }: { summary: ScanSummary }) {
  const endpointAssessment = summary.scan.repository_source_type === 'https_endpoint'
  const cards = [
    { label: endpointAssessment ? 'TLS protocols checked' : 'Files scanned', value: endpointAssessment ? summary.scan.tls_assessment?.protocols.length ?? 0 : summary.counts.files_scanned },
    { label: endpointAssessment ? 'Key exchange groups' : 'Files skipped', value: endpointAssessment ? summary.scan.tls_assessment?.groups.length ?? 0 : summary.counts.files_skipped },
    { label: endpointAssessment ? 'TLS findings' : 'Call-site findings', value: summary.counts.findings },
    { label: 'Unique crypto assets', value: summary.counts.unique_assets },
    { label: 'Quantum vulnerable', value: summary.counts.quantum_vulnerable },
    { label: 'Quantum resistant', value: summary.counts.quantum_resistant },
    { label: 'Needs review', value: summary.counts.needs_review },
    { label: 'High-priority items', value: summary.counts.high_priority },
  ]
  return (
    <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
      {cards.map(c => (
        <div key={c.label} className="card">
          <p className="text-xs uppercase tracking-wide text-slate-400">{c.label}</p>
          <p className="mt-2 text-2xl font-semibold">{c.value}</p>
        </div>
      ))}
    </div>
  )
}
