import { Link } from 'react-router-dom'
import { AlertCircle, ArrowRight, CheckCircle2, LoaderCircle, ScanSearch } from 'lucide-react'
import type { ScanSummary } from '../types'

export default function ScanProgress({ scanId, summary }: { scanId: string; summary: ScanSummary }) {
  const status = summary.scan.scan_status
  const complete = status === 'completed' || status === 'incomplete'
  const failed = status === 'failed'
  const endpointAssessment = summary.scan.repository_source_type === 'https_endpoint'
  const total = summary.scan.total_files ?? 0
  const scanned = summary.counts.files_scanned ?? 0
  const percent = status === 'completed' ? 100 : total ? Math.min(100, Math.round((scanned / total) * 100)) : 0

  return (
    <div className="mx-auto max-w-3xl space-y-6 py-5">
      <div className="text-center">
        <p className="eyebrow">{endpointAssessment ? 'HTTPS endpoint assessment' : 'Repository assessment'}</p>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white">{failed ? 'Assessment stopped' : complete ? 'Assessment complete' : 'Analysis in progress'}</h1>
        <p className="mt-2 truncate text-sm text-slate-400">{summary.scan.repository_name}</p>
      </div>

      <section className="card overflow-hidden !p-0">
        <div className="flex items-center gap-4 border-b border-white/[0.07] p-5 sm:p-6">
          <span className={`flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl ${failed ? 'bg-rose-300/10 text-rose-200' : complete ? 'bg-emerald-300/10 text-emerald-200' : 'bg-cyan-300/10 text-cyan-100'}`}>
            {failed ? <AlertCircle className="h-5 w-5" /> : complete ? <CheckCircle2 className="h-5 w-5" /> : <LoaderCircle className="h-5 w-5 animate-spin" />}
          </span>
          <div className="min-w-0 flex-1"><p className="text-sm font-semibold capitalize text-slate-100">{status}</p><p className="mt-1 text-xs text-slate-500">{failed ? summary.scan.error_summary || 'The scan could not be completed.' : complete ? 'Review the results and export the cryptographic inventory.' : endpointAssessment ? 'Probing TLS handshakes, key exchange groups, and the presented certificate.' : 'Scanning supported source files for cryptographic usage.'}</p></div>
          {!failed && <span className="text-lg font-semibold tabular-nums text-slate-200">{percent}%</span>}
        </div>
        {!failed && <div className="p-5 sm:p-6">
          <div className="h-2 overflow-hidden rounded-full bg-white/[0.07]" role="progressbar" aria-label="Scan progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={percent}>
            <div className={`h-full rounded-full transition-all duration-700 ${complete ? 'bg-emerald-300' : 'bg-cyan-300'}`} style={{ width: `${percent}%` }} />
          </div>
          <div className="mt-5 grid grid-cols-3 divide-x divide-white/[0.07] text-center">
            <div className="px-2"><p className="text-xl font-semibold tabular-nums text-white">{endpointAssessment ? summary.scan.tls_assessment?.protocols.length ?? 0 : scanned}</p><p className="mt-1 text-[10px] uppercase tracking-wide text-slate-500">{endpointAssessment ? 'Protocols checked' : 'Files scanned'}</p></div>
            <div className="px-2"><p className="text-xl font-semibold tabular-nums text-white">{endpointAssessment ? summary.scan.tls_assessment?.groups.length ?? 0 : summary.counts.files_skipped}</p><p className="mt-1 text-[10px] uppercase tracking-wide text-slate-500">{endpointAssessment ? 'Groups probed' : 'Files skipped'}</p></div>
            <div className="px-2"><p className="text-xl font-semibold tabular-nums text-white">{summary.counts.findings}</p><p className="mt-1 text-[10px] uppercase tracking-wide text-slate-500">Findings</p></div>
          </div>
        </div>}
        {failed && <div className="p-5 sm:p-6"><p className="text-xs leading-5 text-slate-400">{endpointAssessment ? 'Check that the endpoint is reachable over HTTPS and resolves to public IP addresses.' : 'Check the repository URL or archive and try again.'} If the issue continues, review the backend logs for the scan error.</p></div>}
      </section>

      {complete && <div className="flex justify-center"><Link to={`/scans/${scanId}`} className="btn-primary">Open audit dashboard <ArrowRight className="h-4 w-4" /></Link></div>}
      {!complete && !failed && <p className="flex items-center justify-center gap-2 text-xs text-slate-500"><ScanSearch className="h-4 w-4 text-cyan-200" />This page updates automatically while the scan runs.</p>}
    </div>
  )
}
