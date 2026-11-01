import { useParams } from 'react-router-dom'
import { ExportButtons } from '../components/ExportButtons'

export default function Reports() {
  const { scanId } = useParams<{ scanId: string }>()
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Reports</h1>
      <div className="card">
        <h2 className="font-semibold">Executive PDF report</h2>
        <p className="mt-2 text-sm text-slate-400">Generate a client-readable PQC exposure report with executive summary, ranked findings, migration roadmap, and scanner limitations.</p>
        <div className="mt-4"><ExportButtons scanId={scanId!} /></div>
      </div>
    </div>
  )
}
