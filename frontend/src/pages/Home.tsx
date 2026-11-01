import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  ArrowRight, ArrowUpRight, Atom, BadgeCheck, FileCheck2, FileSearch,
  FileText, Fingerprint, FolderGit2, ShieldAlert, ShieldCheck,
} from 'lucide-react'
import { listScans } from '../services/api'
import type { ScanItem } from '../types'

const capabilities = [
  { icon: FileSearch, title: 'Cryptographic discovery', description: 'Inspect application code, web markup, dependency manifests, and common configuration across major languages and platforms.' },
  { icon: Atom, title: 'Quantum risk context', description: 'Classify algorithms against current post-quantum guidance and highlight items that need review.' },
  { icon: FileCheck2, title: 'CBOM and reporting', description: 'Create CycloneDX 1.7 cryptographic inventories and executive reports for follow-up.' },
]

function statusTone(status?: string) {
  if (status === 'completed') return 'bg-emerald-300/10 text-emerald-200'
  if (status === 'running') return 'bg-cyan-300/10 text-cyan-200'
  if (status === 'failed') return 'bg-rose-300/10 text-rose-200'
  return 'bg-amber-300/10 text-amber-200'
}

export default function Home() {
  const { data: scans = [] } = useQuery<ScanItem[]>({ queryKey: ['scans'], queryFn: listScans })
  const recent = scans.slice(0, 4)
  const findings = scans.reduce((sum, scan) => sum + (scan.total_findings ?? 0), 0)
  const completed = scans.filter(scan => scan.scan_status === 'completed').length

  return (
    <div className="space-y-9 pb-8">
      <section className="relative isolate overflow-hidden rounded-[28px] border border-white/[0.09] bg-[#0c1727] px-6 py-9 shadow-[0_24px_80px_rgba(0,0,0,.25)] sm:px-10 sm:py-12 lg:px-14 lg:py-14">
        <div className="absolute inset-0 -z-10 bg-[radial-gradient(ellipse_at_82%_38%,rgba(34,211,238,.15),transparent_34%),linear-gradient(115deg,rgba(12,23,39,.15),rgba(7,13,23,.65))]" />
        <div className="absolute -right-12 -top-28 -z-10 h-80 w-80 rounded-full border border-cyan-100/[0.06] sm:right-14 sm:top-[-8rem] sm:h-[28rem] sm:w-[28rem]">
          <div className="absolute inset-8 rounded-full border border-cyan-100/[0.06]" />
          <div className="absolute inset-16 rounded-full border border-cyan-100/[0.06]" />
          <div className="absolute left-1/2 top-1/2 flex h-20 w-20 -translate-x-1/2 -translate-y-1/2 items-center justify-center rounded-3xl border border-cyan-200/20 bg-cyan-300/[0.08] text-cyan-100 shadow-[0_0_70px_rgba(34,211,238,.14)]">
            <Fingerprint className="h-9 w-9" strokeWidth={1.2} />
          </div>
        </div>
        <div className="max-w-2xl">
          <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-cyan-200/15 bg-cyan-200/[0.06] px-3 py-1.5 text-[11px] font-medium tracking-wide text-cyan-100">
            <span className="h-1.5 w-1.5 rounded-full bg-cyan-300 shadow-[0_0_10px_rgba(103,232,249,.8)]" />
            POST-QUANTUM READINESS WORKSPACE
          </div>
          <h1 className="max-w-xl text-3xl font-semibold leading-[1.12] tracking-[-.035em] text-white sm:text-5xl">
            Make your cryptographic exposure visible.
          </h1>
          <p className="mt-5 max-w-xl text-sm leading-7 text-slate-300 sm:text-base">
            Assess source repositories, understand quantum risk, and build a prioritized path toward cryptographic agility.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <Link to="/new-audit" className="btn-primary !px-5 !py-3">Start an assessment <ArrowRight className="h-4 w-4" /></Link>
            <Link to="/projects" className="btn-secondary !px-5 !py-3">Browse audit history</Link>
          </div>
          <div className="mt-8 flex flex-wrap items-center gap-x-5 gap-y-2 text-xs text-slate-400">
            <span className="inline-flex items-center gap-1.5"><ShieldCheck className="h-3.5 w-3.5 text-emerald-300" /> Static analysis</span>
            <span className="hidden h-3 w-px bg-white/10 sm:block" />
            <span>CycloneDX 1.7 CBOM output</span>
            <span className="hidden h-3 w-px bg-white/10 sm:block" />
            <span>Deterministic findings</span>
          </div>
        </div>
      </section>

      <section className="grid gap-3 sm:grid-cols-3">
        <div className="card flex items-center gap-4 !p-4 sm:!p-5">
          <span className="flex h-11 w-11 items-center justify-center rounded-xl bg-indigo-300/[0.09] text-indigo-200"><FolderGit2 className="h-5 w-5" /></span>
          <div><p className="text-xs text-slate-400">Repositories assessed</p><p className="mt-1 text-2xl font-semibold tracking-tight text-white">{scans.length}</p></div>
        </div>
        <div className="card flex items-center gap-4 !p-4 sm:!p-5">
          <span className="flex h-11 w-11 items-center justify-center rounded-xl bg-emerald-300/[0.09] text-emerald-200"><BadgeCheck className="h-5 w-5" /></span>
          <div><p className="text-xs text-slate-400">Completed assessments</p><p className="mt-1 text-2xl font-semibold tracking-tight text-white">{completed}</p></div>
        </div>
        <div className="card flex items-center gap-4 !p-4 sm:!p-5">
          <span className="flex h-11 w-11 items-center justify-center rounded-xl bg-amber-300/[0.09] text-amber-200"><ShieldAlert className="h-5 w-5" /></span>
          <div><p className="text-xs text-slate-400">Cryptographic findings</p><p className="mt-1 text-2xl font-semibold tracking-tight text-white">{findings}</p></div>
        </div>
      </section>

      <section className="grid gap-8 lg:grid-cols-[minmax(0,1fr)_310px]">
        <div className="space-y-4">
          <div className="flex items-end justify-between gap-4">
            <div><p className="eyebrow">Workspace</p><h2 className="mt-2 section-title">Recent assessments</h2></div>
            <Link to="/projects" className="inline-flex items-center gap-1.5 text-xs font-medium text-cyan-200 transition hover:text-cyan-100">All audits <ArrowRight className="h-3.5 w-3.5" /></Link>
          </div>
          {recent.length ? <div className="overflow-hidden rounded-2xl border border-white/[0.08] bg-[#0d1422]/85">
            {recent.map((scan, index) => (
              <Link key={scan.scan_id} to={`/scans/${scan.scan_id}`} className={`group flex items-center justify-between gap-4 px-4 py-4 transition hover:bg-white/[0.035] sm:px-5 ${index ? 'border-t border-white/[0.06]' : ''}`}>
                <div className="flex min-w-0 items-center gap-3.5">
                  <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-white/[0.07] bg-white/[0.035] text-slate-300"><FolderGit2 className="h-4 w-4" /></span>
                  <div className="min-w-0"><p className="truncate text-sm font-medium text-slate-100 group-hover:text-white">{scan.repository_name}</p><p className="mt-1 text-xs text-slate-500">{scan.total_findings ?? 0} findings <span className="mx-1 text-slate-700">·</span> {scan.scanned_files ?? 0} files scanned</p></div>
                </div>
                <div className="flex shrink-0 items-center gap-3"><span className={`rounded-full px-2.5 py-1 text-[10px] font-medium capitalize ${statusTone(scan.scan_status)}`}>{scan.scan_status}</span><ArrowUpRight className="h-4 w-4 text-slate-600 transition group-hover:text-cyan-200" /></div>
              </Link>
            ))}
          </div> : <div className="card flex flex-col items-start gap-4 py-7 sm:flex-row sm:items-center sm:justify-between"><div><p className="text-sm font-medium text-slate-100">Your audit history will appear here</p><p className="mt-1 text-xs text-slate-400">Start a repository assessment from a public Git URL or ZIP archive.</p></div><Link to="/new-audit" className="btn-secondary !py-2 text-xs">Create first audit <ArrowRight className="h-3.5 w-3.5" /></Link></div>}
        </div>

        <aside className="space-y-4">
          <div><p className="eyebrow">Platform</p><h2 className="mt-2 section-title">Built for practical review</h2></div>
          <div className="space-y-2.5">
            {capabilities.map(item => <div key={item.title} className="rounded-2xl border border-white/[0.07] bg-white/[0.025] p-4">
              <div className="flex items-center gap-2.5"><item.icon className="h-4 w-4 text-cyan-200" /><h3 className="text-[13px] font-medium text-slate-100">{item.title}</h3></div>
              <p className="mt-2 pl-[26px] text-xs leading-5 text-slate-400">{item.description}</p>
            </div>)}
          </div>
          <div className="rounded-2xl border border-amber-200/10 bg-amber-100/[0.035] p-4">
            <div className="flex items-center gap-2 text-amber-100"><ShieldAlert className="h-4 w-4" /><p className="text-xs font-semibold">Coverage note</p></div>
            <p className="mt-2 text-xs leading-5 text-slate-400">Results reflect supported source files and static analysis rules. Review findings alongside runtime, infrastructure, and vendor cryptography inventories.</p>
          </div>
        </aside>
      </section>
    </div>
  )
}
