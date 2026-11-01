import { useMemo, useState } from 'react'
import type { Finding } from '../types'
import RiskBadge from './RiskBadge'
import FindingDetailsPanel from './FindingDetailsPanel'

export default function CryptoFindingsTable({ findings }: { findings: Finding[] }) {
  const [selected, setSelected] = useState<Finding | null>(null)
  const [search, setSearch] = useState('')
  const [classification, setClassification] = useState('')

  const filtered = useMemo(() =>
    findings
      .filter(f => `${f.algorithm} ${f.file_path} ${f.library_name}`.toLowerCase().includes(search.toLowerCase()))
      .filter(f => !classification || f.quantum_classification === classification)
      .sort((a,b) => b.severity_score - a.severity_score),
  [findings, search, classification])

  return (
    <div className="card">
      <div className="mb-4 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <input value={search} onChange={e => setSearch(e.target.value)}
          placeholder="Search algorithm, library, or file"
          className="w-full rounded-lg border border-navy-700 bg-navy-800 px-3 py-2 text-sm md:max-w-sm" />
        <select value={classification} onChange={e => setClassification(e.target.value)}
          className="rounded-lg border border-navy-700 bg-navy-800 px-3 py-2 text-sm">
          <option value="">All classifications</option>
          <option>Quantum Vulnerable</option>
          <option>Quantum Resistant Under Current Knowledge</option>
          <option>Unknown / Needs Review</option>
        </select>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-navy-700 text-xs uppercase text-slate-400">
            <tr><th className="p-3">Algorithm</th><th className="p-3">Operation</th><th className="p-3">Library</th>
                <th className="p-3">File</th><th className="p-3">Quantum risk</th><th className="p-3">Severity</th><th className="p-3">Confidence</th></tr>
          </thead>
          <tbody>
            {filtered.map(f => (
              <tr key={f.finding_id} onClick={() => setSelected(f)}
                  className="cursor-pointer border-b border-navy-800 hover:bg-navy-800">
                <td className="p-3 font-medium">{f.algorithm}</td>
                <td className="p-3">{f.crypto_operation}</td>
                <td className="p-3">{f.library_name}</td>
                <td className="p-3 text-slate-400">{f.file_path.split(/[/\\]/).pop()}:{f.start_line}</td>
                <td className="p-3"><RiskBadge classification={f.quantum_classification} /></td>
                <td className="p-3">{f.severity_category} ({f.severity_score})</td>
                <td className="p-3">{f.detection_confidence}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {selected && <FindingDetailsPanel finding={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}
