import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation } from '@tanstack/react-query'
import { AlertCircle, ArrowRight, Check, FileArchive, GitBranch, Globe2, LockKeyhole, ShieldCheck } from 'lucide-react'
import { scanHttpsEndpoint, scanRepositorySource } from '../services/api'
import RepositoryUpload from '../components/RepositoryUpload'
import ScanConfiguration from '../components/ScanConfiguration'
import type { ScanConfig } from '../types'

export default function NewAudit() {
  const navigate = useNavigate()
  const [sourceMode, setSourceMode] = useState<'repository' | 'https'>('repository')
  const [sourceType, setSourceType] = useState<'zip' | 'github'>('zip')
  const [file, setFile] = useState<File | null>(null)
  const [gitUrl, setGitUrl] = useState('')
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const [config, setConfig] = useState<ScanConfig>({
    scan_name: 'Authorized cryptography assessment',
    business_criticality: 'High',
    data_sensitivity: 'Confidential',
    data_retention_horizon: '3-7 years',
    external_exposure: 'Internal',
    tls_target_url: '',
  })

  const mutation = useMutation({
    mutationFn: async () => {
      setErrorMessage(null)
      if (sourceMode === 'https') {
        if (!config.tls_target_url?.trim()) throw new Error('Enter an HTTPS endpoint to assess')
        return scanHttpsEndpoint({
          scan_name: config.scan_name,
          target_url: config.tls_target_url.trim(),
          business_context: {
            business_criticality: config.business_criticality,
            data_sensitivity: config.data_sensitivity,
            data_retention_horizon: config.data_retention_horizon,
            external_exposure: config.external_exposure,
          },
        })
      }
      if (sourceType === 'zip') {
        if (!file) throw new Error('Select a ZIP archive first')
      } else {
        if (!gitUrl.trim()) throw new Error('Enter a valid HTTPS repository URL')
        if (!gitUrl.startsWith('https://')) throw new Error('Only HTTPS repository URLs are supported')
      }
      return scanRepositorySource(sourceType, sourceType === 'zip' ? file : null, gitUrl.trim(), config)
    },
    onSuccess: data => navigate(`/scans/${data.scan_id}/progress`),
    onError: (err: any) => setErrorMessage(err.response?.data?.detail || err.message || 'Scan could not be started.'),
  })

  const canSubmit = sourceMode === 'repository'
    ? sourceType === 'zip' ? Boolean(file) : Boolean(gitUrl.trim())
    : Boolean(config.tls_target_url?.trim())
  const selectMode = (mode: 'repository' | 'https') => {
    setSourceMode(mode)
    setErrorMessage(null)
  }

  return (
    <div className="mx-auto max-w-6xl space-y-8 pb-8">
      <div className="flex flex-col justify-between gap-5 border-b border-white/[0.07] pb-6 sm:flex-row sm:items-end">
        <div>
          <p className="eyebrow">New assessment</p>
          <h1 className="mt-2 text-3xl font-semibold tracking-[-.03em] text-white">Configure cryptography assessment</h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">Scan repository source code or assess the live TLS posture of an HTTPS endpoint.</p>
        </div>
        <div className="flex items-center gap-2 text-xs text-slate-500"><LockKeyhole className="h-4 w-4 text-emerald-300" />{sourceMode === 'https' ? 'Live TLS endpoint probe' : 'Source code is analyzed statically'}</div>
      </div>

      <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,1fr)_300px]">
        <div className="space-y-5">
          <section className="card !p-0">
            <div className="border-b border-white/[0.07] px-5 py-4 sm:px-6">
              <p className="text-sm font-semibold text-slate-100">Assessment source</p>
              <p className="mt-1 text-xs text-slate-500">Choose a repository source or a standalone live TLS assessment.</p>
            </div>
            <div className="grid gap-3 p-4 sm:grid-cols-2 sm:p-5">
              <button type="button" aria-pressed={sourceMode === 'repository'} onClick={() => selectMode('repository')}
                className={`rounded-xl border p-4 text-left transition ${sourceMode === 'repository' ? 'border-cyan-300/35 bg-cyan-300/[0.07] shadow-[inset_0_0_0_1px_rgba(103,232,249,.06)]' : 'border-white/[0.07] bg-white/[0.02] hover:border-white/15 hover:bg-white/[0.04]'}`}>
                <span className={`flex h-9 w-9 items-center justify-center gap-1 rounded-lg ${sourceMode === 'repository' ? 'bg-cyan-200/10 text-cyan-100' : 'bg-white/[0.05] text-slate-400'}`}><GitBranch className="h-4 w-4" /><FileArchive className="h-3.5 w-3.5" /></span>
                <span className="mt-3 flex items-center justify-between text-sm font-medium text-slate-100">Repository source {sourceMode === 'repository' && <Check className="h-4 w-4 text-cyan-200" />}</span>
                <span className="mt-1 block text-xs leading-5 text-slate-500">Use a public Git URL or a local ZIP archive.</span>
              </button>
              <button type="button" aria-pressed={sourceMode === 'https'} onClick={() => selectMode('https')}
                className={`rounded-xl border p-4 text-left transition ${sourceMode === 'https' ? 'border-cyan-300/35 bg-cyan-300/[0.07] shadow-[inset_0_0_0_1px_rgba(103,232,249,.06)]' : 'border-white/[0.07] bg-white/[0.02] hover:border-white/15 hover:bg-white/[0.04]'}`}>
                <span className={`flex h-9 w-9 items-center justify-center rounded-lg ${sourceMode === 'https' ? 'bg-cyan-200/10 text-cyan-100' : 'bg-white/[0.05] text-slate-400'}`}><Globe2 className="h-4 w-4" /></span>
                <span className="mt-3 flex items-center justify-between text-sm font-medium text-slate-100">HTTPS endpoint {sourceMode === 'https' && <Check className="h-4 w-4 text-cyan-200" />}</span>
                <span className="mt-1 block text-xs leading-5 text-slate-500">Assess TLS directly, without repository files.</span>
              </button>
            </div>

            <div className="border-t border-white/[0.07] p-4 sm:p-5">
              {sourceMode === 'repository' ? <div className="space-y-4">
                <div className="inline-flex rounded-xl border border-white/[0.08] bg-black/10 p-1" role="group" aria-label="Repository source type">
                  <button type="button" aria-pressed={sourceType === 'github'} onClick={() => { setSourceType('github'); setErrorMessage(null) }}
                    className={`inline-flex items-center gap-2 rounded-lg px-3 py-2 text-xs font-medium transition ${sourceType === 'github' ? 'bg-cyan-200/10 text-cyan-100' : 'text-slate-400 hover:text-slate-200'}`}><GitBranch className="h-3.5 w-3.5" /> Public Git URL</button>
                  <button type="button" aria-pressed={sourceType === 'zip'} onClick={() => { setSourceType('zip'); setErrorMessage(null) }}
                    className={`inline-flex items-center gap-2 rounded-lg px-3 py-2 text-xs font-medium transition ${sourceType === 'zip' ? 'bg-cyan-200/10 text-cyan-100' : 'text-slate-400 hover:text-slate-200'}`}><FileArchive className="h-3.5 w-3.5" /> ZIP archive</button>
                </div>
                {sourceType === 'github' ? <div className="space-y-3">
                  <label htmlFor="repository-url" className="block text-xs font-medium text-slate-300">Public Git repository URL</label>
                  <input id="repository-url" type="url" value={gitUrl} onChange={event => setGitUrl(event.target.value)} placeholder="https://github.com/organization/repository" className="field-control" />
                  <p className="text-xs leading-5 text-slate-500">Public repositories on GitHub, GitLab, and Bitbucket are supported. Private repository credentials are not accepted.</p>
                </div> : <RepositoryUpload selectedFile={file} onFileSelected={setFile} />}
              </div> : <div className="space-y-3">
                <label htmlFor="tls-target" className="block text-xs font-medium text-slate-300">HTTPS endpoint</label>
                <input id="tls-target" type="url" value={config.tls_target_url || ''} onChange={event => setConfig({ ...config, tls_target_url: event.target.value })} placeholder="https://service.example.com" className="field-control" />
                <p className="text-xs leading-5 text-slate-500">The scanner probes TLS 1.2/1.3, key exchange groups, cipher suites, and the presented certificate. No source code is needed.</p>
              </div>}
            </div>
          </section>

          <ScanConfiguration config={config} onChange={setConfig} />
          {sourceMode !== 'https' && <section className="card">
            <p className="text-sm font-semibold text-slate-100">Optional live TLS assessment</p>
            <p className="mt-1 text-xs leading-5 text-slate-500">Probe an HTTPS endpoint you are authorized to assess. The scan tests TLS 1.2/1.3, supported groups, negotiated cipher suites, and the presented certificate.</p>
            <label htmlFor="tls-target" className="mt-4 block text-xs font-medium text-slate-300">HTTPS endpoint</label>
            <input id="tls-target" type="url" value={config.tls_target_url || ''} onChange={event => setConfig({ ...config, tls_target_url: event.target.value })} placeholder="https://service.example.com" className="field-control mt-1.5" />
          </section>}
        </div>

        <aside className="space-y-4 lg:sticky lg:top-24">
          <div className="card !p-0">
            <div className="border-b border-white/[0.07] px-5 py-4">
              <p className="text-sm font-semibold text-slate-100">Assessment summary</p>
              <p className="mt-1 truncate text-xs text-slate-500">{config.scan_name || 'Unnamed assessment'}</p>
            </div>
            <div className="space-y-4 p-5">
              <div className="flex items-start gap-3"><span className="mt-0.5 text-cyan-200">{sourceMode === 'https' ? <Globe2 className="h-4 w-4" /> : sourceType === 'zip' ? <FileArchive className="h-4 w-4" /> : <GitBranch className="h-4 w-4" />}</span><div><p className="text-xs font-medium text-slate-200">{sourceMode === 'https' ? 'HTTPS endpoint' : sourceType === 'zip' ? 'ZIP repository' : 'Public Git repository'}</p><p className="mt-1 break-all text-xs text-slate-500">{sourceMode === 'https' ? config.tls_target_url || 'HTTPS endpoint not provided' : sourceType === 'zip' ? file?.name || 'ZIP archive not selected' : gitUrl || 'Git URL not provided'}</p></div></div>
              {sourceMode !== 'https' && config.tls_target_url?.trim() && <div className="flex items-start gap-3"><span className="mt-0.5 text-cyan-200"><LockKeyhole className="h-4 w-4" /></span><div><p className="text-xs font-medium text-slate-200">TLS endpoint</p><p className="mt-1 break-all text-xs text-slate-500">{config.tls_target_url}</p></div></div>}
              {sourceMode === 'repository' && <div className="flex items-start gap-3"><span className="mt-0.5 text-cyan-200"><ShieldCheck className="h-4 w-4" /></span><div><p className="text-xs font-medium text-slate-200">Source coverage</p><p className="mt-1 text-xs leading-5 text-slate-500">Python, JavaScript/TypeScript, Java/Kotlin/Scala, Go, HTML, C/C++, Rust, C#, PHP, Ruby, Swift, shell, SQL, and common config files</p></div></div>}
              <div className="border-t border-white/[0.07] pt-4"><p className="text-[10px] font-semibold uppercase tracking-[.14em] text-slate-500">Business criticality</p><p className="mt-1 text-sm text-slate-200">{config.business_criticality}</p></div>
              <div><p className="text-[10px] font-semibold uppercase tracking-[.14em] text-slate-500">Data sensitivity</p><p className="mt-1 text-sm text-slate-200">{config.data_sensitivity}</p></div>
              <div><p className="text-[10px] font-semibold uppercase tracking-[.14em] text-slate-500">Exposure</p><p className="mt-1 text-sm text-slate-200">{config.external_exposure}</p></div>
            </div>
            <div className="border-t border-white/[0.07] p-5">
              <button className="btn-primary w-full" disabled={!canSubmit || mutation.isPending} onClick={() => mutation.mutate()}>
                {mutation.isPending ? 'Preparing assessment…' : 'Start assessment'} {!mutation.isPending && <ArrowRight className="h-4 w-4" />}
              </button>
              {errorMessage && <div role="alert" className="mt-3 flex items-start gap-2 rounded-xl border border-rose-300/15 bg-rose-300/[0.06] p-3 text-xs leading-5 text-rose-200"><AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />{errorMessage}</div>}
              <p className="mt-3 text-center text-[10px] leading-4 text-slate-600">{sourceMode === 'https' ? 'Only TLS handshakes are performed; no source code is uploaded.' : 'Repository code is not executed during static analysis.'}</p>
            </div>
          </div>
        </aside>
      </div>
    </div>
  )
}
