import { AlertTriangle, CheckCircle2, CircleHelp, Globe2, ShieldCheck } from 'lucide-react'
import type { TlsAssessment } from '../types'

function statusStyle(status: string) {
  if (status === 'confirmed' || status.includes('confirmed')) return 'bg-emerald-300/10 text-emerald-200'
  if (status === 'not_supported' || status === 'not_pqc') return 'bg-rose-300/10 text-rose-200'
  return 'bg-amber-300/10 text-amber-200'
}

export default function TlsAssessmentPanel({ assessment }: { assessment: TlsAssessment }) {
  if (assessment.status === 'rejected' || assessment.status === 'inconclusive') return (
    <section className="card border-amber-200/10">
      <div className="flex items-center gap-2"><CircleHelp className="h-4 w-4 text-amber-200" /><h2 className="section-title">TLS endpoint assessment</h2></div>
      <p className="mt-3 text-sm text-slate-300">{assessment.error || 'The TLS assessment could not be completed.'}</p>
    </section>
  )
  const cert = assessment.certificate
  return (
    <section className="card space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div><p className="eyebrow">Live endpoint assessment</p><h2 className="mt-2 section-title">TLS posture</h2><p className="mt-1 break-all text-xs text-slate-500">{assessment.target}</p></div>
        <span className="inline-flex items-center gap-1.5 rounded-full bg-cyan-300/[0.08] px-3 py-1.5 text-[10px] font-medium text-cyan-100"><Globe2 className="h-3.5 w-3.5" /> Active TLS probe</span>
      </div>

      <div className="grid gap-3 md:grid-cols-2">
        {assessment.protocols.map(protocol => <div key={protocol.version} className="rounded-xl border border-white/[0.07] bg-white/[0.02] p-4">
          <div className="flex items-center justify-between gap-3"><p className="text-sm font-semibold text-slate-100">{protocol.version}</p><span className={`rounded-full px-2.5 py-1 text-[10px] font-medium ${statusStyle(protocol.status === 'confirmed' ? protocol.pqc_status : protocol.status)}`}>{protocol.status === 'confirmed' ? protocol.pqc_status.replace(/_/g, ' ') : protocol.status.replace(/_/g, ' ')}</span></div>
          {protocol.cipher_suite && <div className="mt-3 space-y-1 text-xs"><p className="text-slate-300">{protocol.cipher_suite.name}</p><p className="font-mono text-[10px] text-slate-500">IANA {protocol.cipher_suite.iana_id || 'identifier unavailable'}</p></div>}
          {protocol.reason && <p className="mt-2 text-xs leading-5 text-slate-500">{protocol.reason}</p>}
        </div>)}
      </div>

      <div>
        <div className="mb-2 flex items-center gap-2"><ShieldCheck className="h-4 w-4 text-cyan-200" /><h3 className="text-xs font-semibold text-slate-200">TLS 1.3 supported groups</h3></div>
        <div className="overflow-hidden rounded-xl border border-white/[0.07]">
          {assessment.groups.map((group, index) => <div key={group.name} className={`flex flex-wrap items-center justify-between gap-2 px-3 py-2.5 ${index ? 'border-t border-white/[0.06]' : ''}`}>
            <div className="min-w-0"><p className="text-xs font-medium text-slate-200">{group.name}</p><p className="mt-0.5 font-mono text-[10px] text-slate-600">{group.iana_id}{group.pqc_algorithm ? ` · ${group.pqc_algorithm}` : ''}</p></div>
            <div className="flex items-center gap-2"><span className={`rounded-full px-2 py-1 text-[10px] font-medium ${statusStyle(group.status)}`}>{group.status.replace(/_/g, ' ')}</span>{group.negotiated_group && <span className="inline-flex items-center gap-1 text-[10px] text-emerald-200"><CheckCircle2 className="h-3 w-3" /> negotiated {group.negotiated_group}</span>}</div>
          </div>)}
        </div>
      </div>

      {cert && !cert.parse_error && <div className="rounded-xl border border-white/[0.07] bg-white/[0.02] p-4">
        <div className="flex items-center gap-2"><ShieldCheck className="h-4 w-4 text-cyan-200" /><h3 className="text-xs font-semibold text-slate-200">Presented certificate</h3></div>
        <div className="mt-3 grid gap-3 text-xs sm:grid-cols-2">
          <div><p className="text-slate-500">Public key</p><p className="mt-1 text-slate-200">{cert.public_key_algorithm}{cert.public_key_bits ? `-${cert.public_key_bits}` : ''} <span className="text-slate-500">· {cert.public_key_quantum_status?.replace(/_/g, ' ')}</span></p></div>
          <div><p className="text-slate-500">Certificate signature</p><p className="mt-1 break-words text-slate-200">{cert.signature_algorithm} <span className="text-slate-500">· {cert.signature_quantum_status?.replace(/_/g, ' ')}</span></p></div>
        </div>
        <p className="mt-3 flex items-start gap-1.5 text-[10px] leading-4 text-amber-200/80"><AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" />The probe inspects the presented certificate but does not validate its trust chain.</p>
      </div>}

      {assessment.findings.length > 0 && <div>
        <h3 className="mb-2 text-xs font-semibold text-slate-200">TLS findings</h3>
        <div className="space-y-2">{assessment.findings.map(item => <div key={item.title} className="flex items-start gap-3 rounded-xl border border-white/[0.06] bg-white/[0.02] p-3">
          <span className={`mt-0.5 rounded-md px-2 py-1 text-[10px] font-semibold ${statusStyle(item.severity === 'Low' ? 'confirmed' : 'not_pqc')}`}>{item.severity}</span>
          <div><p className="text-xs font-medium text-slate-200">{item.title}</p><p className="mt-1 text-xs leading-5 text-slate-500">{item.detail}</p></div>
        </div>)}</div>
      </div>}
    </section>
  )
}
