import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { 
  FolderGit2, 
  Search, 
  Trash2, 
  ExternalLink, 
  Plus, 
  FileArchive, 
  GitBranch, 
  Globe2,
  ShieldAlert, 
  CheckCircle2, 
  Clock, 
  AlertCircle 
} from 'lucide-react'
import { listScans, deleteScan } from '../services/api'
import LoadingSkeleton from '../components/LoadingSkeleton'
import ErrorState from '../components/ErrorState'
import type { ScanItem } from '../types'

export default function ProjectList() {
  const queryClient = useQueryClient()
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('')

  const { data: scans, isLoading, isError } = useQuery<ScanItem[]>({
    queryKey: ['scans'],
    queryFn: listScans,
    refetchInterval: 5000,
  })

  const deleteMutation = useMutation({
    mutationFn: (scanId: string) => deleteScan(scanId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
    },
  })

  if (isLoading) return <LoadingSkeleton />
  if (isError || !scans) return <ErrorState message="Unable to load project audits." />

  const filtered = scans.filter(s => {
    const matchesSearch = s.repository_name?.toLowerCase().includes(search.toLowerCase()) ||
                          s.scan_id?.toLowerCase().includes(search.toLowerCase())
    const matchesStatus = !statusFilter || s.scan_status === statusFilter
    return matchesSearch && matchesStatus
  })

  const totalScans = scans.length
  const completedScans = scans.filter(s => s.scan_status === 'completed').length
  const scansWithFindings = scans.filter(s => (s.total_findings || 0) > 0).length

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">Audit Projects & Scans</h1>
          <p className="mt-1 text-sm text-slate-400">
            View, track, and manage cryptographic inventory audits across your repositories.
          </p>
        </div>
        <Link to="/new-audit" className="btn-primary flex items-center gap-2">
          <Plus className="h-4 w-4" /> Start New Audit
        </Link>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <div className="card">
          <p className="text-xs uppercase tracking-wide text-slate-400">Total Audits</p>
          <p className="mt-2 text-2xl font-semibold text-slate-100">{totalScans}</p>
        </div>
        <div className="card">
          <p className="text-xs uppercase tracking-wide text-slate-400">Completed Audits</p>
          <p className="mt-2 text-2xl font-semibold text-emerald-400">{completedScans}</p>
        </div>
        <div className="card">
          <p className="text-xs uppercase tracking-wide text-slate-400">Repositories With Findings</p>
          <p className="mt-2 text-2xl font-semibold text-accent-cyan">{scansWithFindings}</p>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="card flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search by repository name or scan ID..."
            className="w-full rounded-lg border border-navy-700 bg-navy-800 pl-9 pr-3 py-2 text-sm text-slate-100 focus:border-accent-cyan focus:outline-none"
          />
        </div>
        <div className="flex items-center gap-2">
          <select
            value={statusFilter}
            onChange={e => setStatusFilter(e.target.value)}
            className="rounded-lg border border-navy-700 bg-navy-800 px-3 py-2 text-sm text-slate-100 focus:border-accent-cyan focus:outline-none"
          >
            <option value="">All Statuses</option>
            <option value="completed">Completed</option>
            <option value="running">Running</option>
            <option value="queued">Queued</option>
            <option value="failed">Failed</option>
          </select>
        </div>
      </div>

      {/* Projects List / Table */}
      {filtered.length === 0 ? (
        <div className="card py-12 text-center space-y-4">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-navy-800 text-slate-400">
            <FolderGit2 className="h-6 w-6" />
          </div>
          <div>
            <h3 className="font-semibold text-slate-200">No audits found</h3>
            <p className="mt-1 text-sm text-slate-400">
              {search || statusFilter ? 'Try clearing your search or filter parameters.' : 'Get started by running your first cryptographic inventory audit.'}
            </p>
          </div>
          {!search && !statusFilter && (
            <Link to="/new-audit" className="btn-primary inline-flex items-center gap-2">
              <Plus className="h-4 w-4" /> Start New Audit
            </Link>
          )}
        </div>
      ) : (
        <div className="space-y-3">
          {filtered.map(scan => {
            const isCompleted = scan.scan_status === 'completed'
            const isRunning = scan.scan_status === 'running'
            const isFailed = scan.scan_status === 'failed'
            const isQueued = scan.scan_status === 'queued'

            return (
              <div
                key={scan.scan_id}
                className="card flex flex-col justify-between gap-4 transition hover:border-navy-600 sm:flex-row sm:items-center"
              >
                <div className="space-y-1.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-semibold text-base text-slate-100">
                      {scan.repository_name || 'Untitled assessment'}
                    </span>
                    <span className="flex items-center gap-1 rounded bg-navy-800 px-2 py-0.5 text-xs text-slate-400 border border-navy-700">
                      {scan.repository_source_type === 'https_endpoint' ? (
                        <>
                          <Globe2 className="h-3 w-3 text-accent-cyan" /> HTTPS
                        </>
                      ) : scan.repository_source_type === 'public_git' ? (
                        <>
                          <GitBranch className="h-3 w-3 text-accent-cyan" /> Git
                        </>
                      ) : (
                        <>
                          <FileArchive className="h-3 w-3 text-accent-cyan" /> ZIP
                        </>
                      )}
                    </span>
                    <span
                      className={`flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium border ${
                        isCompleted
                          ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300'
                          : isRunning
                          ? 'border-cyan-500/40 bg-cyan-500/10 text-cyan-300 animate-pulse'
                          : isFailed
                          ? 'border-red-500/40 bg-red-500/10 text-red-300'
                          : 'border-amber-500/40 bg-amber-500/10 text-amber-300'
                      }`}
                    >
                      {isCompleted && <CheckCircle2 className="h-3 w-3" />}
                      {isRunning && <Clock className="h-3 w-3" />}
                      {isFailed && <AlertCircle className="h-3 w-3" />}
                      {scan.scan_status}
                    </span>
                  </div>

                  <div className="flex flex-wrap items-center gap-4 text-xs text-slate-400">
                    <span>
                      Scan ID: <code className="text-slate-300">{scan.scan_id.slice(0, 8)}...</code>
                    </span>
                    {scan.started_at && (
                      <span>
                        Started: {new Date(scan.started_at).toLocaleString()}
                      </span>
                    )}
                    <span>
                      Files: <strong className="text-slate-200">{scan.scanned_files ?? scan.total_files ?? 0}</strong>
                    </span>
                    <span>
                      Findings:{' '}
                      <strong className={scan.total_findings ? 'text-amber-400 font-semibold' : 'text-slate-200'}>
                        {scan.total_findings ?? 0}
                      </strong>
                    </span>
                    {scan.business_context?.business_criticality && (
                      <span>
                        Criticality: <span className="text-slate-300">{scan.business_context.business_criticality}</span>
                      </span>
                    )}
                  </div>
                  {isFailed && scan.error_summary && (
                    <p className="text-xs text-red-400">Error: {scan.error_summary}</p>
                  )}
                </div>

                <div className="flex flex-wrap items-center gap-2 shrink-0">
                  {isCompleted ? (
                    <>
                      <Link
                        to={`/scans/${scan.scan_id}`}
                        className="btn-primary text-xs flex items-center gap-1.5 py-1.5 px-3"
                      >
                        <ExternalLink className="h-3.5 w-3.5" /> Dashboard
                      </Link>
                      <Link
                        to={`/scans/${scan.scan_id}/findings`}
                        className="btn-secondary text-xs py-1.5 px-3"
                      >
                        Findings
                      </Link>
                      <Link
                        to={`/scans/${scan.scan_id}/cbom`}
                        className="btn-secondary text-xs py-1.5 px-3"
                      >
                        CBOM
                      </Link>
                    </>
                  ) : (
                    <Link
                      to={`/scans/${scan.scan_id}/progress`}
                      className="btn-secondary text-xs flex items-center gap-1.5 py-1.5 px-3"
                    >
                      <Clock className="h-3.5 w-3.5" /> View Progress
                    </Link>
                  )}
                  <button
                    onClick={() => {
                      if (confirm(`Are you sure you want to delete audit "${scan.repository_name}"?`)) {
                        deleteMutation.mutate(scan.scan_id)
                      }
                    }}
                    className="rounded p-2 text-slate-400 hover:text-red-400 hover:bg-navy-800 transition"
                    title="Delete audit record"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
