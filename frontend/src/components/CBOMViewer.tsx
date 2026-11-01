import { useState } from 'react'
import { CheckCircle2, AlertTriangle, Copy, Check, Code, Shield } from 'lucide-react'

interface Props {
  validation: { valid: boolean; errors: { path: string; message: string }[] }
  componentCount: number
  cbom?: any
}

export default function CBOMViewer({ validation, componentCount, cbom }: Props) {
  const [tab, setTab] = useState<'components' | 'json'>('components')
  const [copied, setCopied] = useState(false)

  const components = cbom?.components || []

  const handleCopy = () => {
    if (cbom) {
      navigator.clipboard.writeText(JSON.stringify(cbom, null, 2))
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  return (
    <div className="space-y-6">
      {/* Validation Header */}
      <div className={`card border ${validation.valid ? 'border-emerald-500/30 bg-emerald-500/5' : 'border-red-500/30 bg-red-500/5'}`}>
        <div className="flex items-start gap-3">
          {validation.valid ? (
            <CheckCircle2 className="h-6 w-6 text-emerald-400 shrink-0 mt-0.5" />
          ) : (
            <AlertTriangle className="h-6 w-6 text-red-400 shrink-0 mt-0.5" />
          )}
          <div>
            <h2 className="font-semibold text-lg">
              {validation.valid ? 'CycloneDX 1.7 Specification Valid' : 'CBOM Schema Validation Errors'}
            </h2>
            <p className="mt-1 text-sm text-slate-300">
              {validation.valid
                ? `Successfully synthesized and validated ${componentCount} cryptographic asset ${componentCount === 1 ? 'component' : 'components'} against the official CycloneDX 1.7 JSON schema.`
                : 'The generated inventory did not pass validation against the CycloneDX schema.'}
            </p>
            {!validation.valid && validation.errors?.length > 0 && (
              <ul className="mt-3 space-y-1 rounded bg-navy-900 p-3 text-xs text-red-300">
                {validation.errors.map((e, i) => (
                  <li key={i}>
                    <code className="text-red-400">{e.path}</code>: {e.message}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="card space-y-4">
        <div className="flex items-center justify-between border-b border-navy-700 pb-3">
          <div className="flex gap-2">
            <button
              onClick={() => setTab('components')}
              className={`flex items-center gap-2 rounded-lg px-3 py-1.5 text-sm font-medium transition ${
                tab === 'components' ? 'bg-navy-700 text-white' : 'text-slate-400 hover:bg-navy-800'
              }`}
            >
              <Shield className="h-4 w-4 text-accent-cyan" /> Cryptographic Components ({components.length})
            </button>
            <button
              onClick={() => setTab('json')}
              className={`flex items-center gap-2 rounded-lg px-3 py-1.5 text-sm font-medium transition ${
                tab === 'json' ? 'bg-navy-700 text-white' : 'text-slate-400 hover:bg-navy-800'
              }`}
            >
              <Code className="h-4 w-4 text-accent-cyan" /> CycloneDX JSON
            </button>
          </div>
          {tab === 'json' && cbom && (
            <button
              onClick={handleCopy}
              className="btn-secondary text-xs flex items-center gap-1.5 py-1 px-3"
            >
              {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
              {copied ? 'Copied' : 'Copy JSON'}
            </button>
          )}
        </div>

        {tab === 'components' ? (
          components.length === 0 ? (
            <p className="py-6 text-center text-sm text-slate-400">
              No cryptographic asset components recorded for this repository.
            </p>
          ) : (
            <div className="space-y-3">
              {components.map((comp: any, idx: number) => {
                const props = comp.cryptoProperties?.algorithmProperties || {}
                const customProps = comp.properties || []
                const qClass = customProps.find((p: any) => p.name === 'pqc-auditor:quantumClassification')?.value
                const occurrences = comp.evidence?.occurrences?.length || 0

                return (
                  <div key={idx} className="rounded-lg border border-navy-700 bg-navy-800/40 p-4">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-3">
                        <span className="font-semibold text-slate-100">{comp.name}</span>
                        <span className="rounded bg-navy-700 px-2 py-0.5 text-xs text-slate-300">
                          {props.primitive || 'crypto-asset'}
                        </span>
                        {qClass && (
                          <span
                            className={`rounded-full border px-2 py-0.5 text-xs font-medium ${
                              qClass === 'Quantum Vulnerable'
                                ? 'border-red-500/40 bg-red-500/10 text-red-300'
                                : qClass === 'Quantum Resistant Under Current Knowledge'
                                ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300'
                                : 'border-amber-500/40 bg-amber-500/10 text-amber-300'
                            }`}
                          >
                            {qClass}
                          </span>
                        )}
                      </div>
                      <span className="text-xs text-slate-400">
                        {occurrences} {occurrences === 1 ? 'occurrence' : 'occurrences'}
                      </span>
                    </div>
                    <p className="mt-2 text-xs text-slate-400">{comp.description}</p>
                    <div className="mt-3 flex flex-wrap gap-4 text-xs text-slate-400">
                      <div>
                        <span className="text-slate-500">BOM Reference: </span>
                        <code className="text-slate-300">{comp['bom-ref']}</code>
                      </div>
                      {props.cryptoFunctions && (
                        <div>
                          <span className="text-slate-500">Functions: </span>
                          <span className="text-slate-300">{props.cryptoFunctions.join(', ')}</span>
                        </div>
                      )}
                      <div>
                        <span className="text-slate-500">NIST Quantum Security Level: </span>
                        <span className="text-slate-300">{props.nistQuantumSecurityLevel ?? 0}</span>
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          )
        ) : (
          <pre className="max-h-[500px] overflow-auto rounded-lg bg-navy-950 p-4 font-mono text-xs text-slate-300 border border-navy-800">
            {cbom ? JSON.stringify(cbom, null, 2) : 'No CBOM JSON available.'}
          </pre>
        )}
      </div>
    </div>
  )
}
