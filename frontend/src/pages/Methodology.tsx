import { Atom, BarChart3, Braces, CircleHelp, FileCode2, ShieldCheck } from 'lucide-react'

const sections = [
  { icon: FileCode2, title: 'Static source analysis', text: 'The scanner reads source and configuration files without executing repository code. Python uses AST based call and import analysis with a regex supplement. Other languages use curated API and configuration signatures. HTML, Vue, and Svelte files are checked for embedded web cryptography.' },
  { icon: Atom, title: 'Algorithm classification', text: 'Findings are classified by algorithm family and current quantum exposure. Public key algorithms such as RSA and elliptic curve cryptography are considered vulnerable to a sufficiently capable quantum computer. AES and modern SHA-2 and SHA-3 hashes are treated as resistant under current knowledge.' },
  { icon: BarChart3, title: 'Risk and migration priority', text: 'Severity combines cryptographic evidence with the submitted business context. These scores help teams order investigation and migration work; they are internal decision support, not official NIST ratings.' },
  { icon: Braces, title: 'Inventory output', text: 'The platform maps detected cryptographic evidence into a CycloneDX 1.7 CBOM and provides machine readable findings and an executive report.' },
]

export default function Methodology() {
  return (
    <div className="mx-auto max-w-4xl space-y-7 pb-8">
      <header className="border-b border-white/[0.07] pb-5">
        <p className="eyebrow">How results are produced</p>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white">Methodology</h1>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">A transparent view of how source evidence becomes a prioritized cryptographic inventory.</p>
      </header>
      <div className="grid gap-3 sm:grid-cols-2">
        {sections.map(section => <section className="card" key={section.title}>
          <span className="flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-200/10 bg-cyan-200/[0.06] text-cyan-100"><section.icon className="h-5 w-5" /></span>
          <h2 className="mt-4 text-sm font-semibold text-slate-100">{section.title}</h2>
          <p className="mt-2 text-xs leading-6 text-slate-400">{section.text}</p>
        </section>)}
      </div>
      <div className="rounded-2xl border border-amber-200/10 bg-amber-100/[0.035] p-5">
        <div className="flex items-center gap-2 text-amber-100"><CircleHelp className="h-4 w-4" /><h2 className="text-xs font-semibold">Coverage and interpretation</h2></div>
        <p className="mt-2 text-xs leading-6 text-slate-400">Results only cover supported languages, file types, and detection rules. A missing finding does not establish that cryptography is absent. Confirm material decisions with code owners and review runtime services, certificates, hardware, cloud settings, and compiled dependencies separately.</p>
        <p className="mt-3 flex items-start gap-2 text-xs leading-5 text-slate-500"><ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-cyan-200/70" /> Findings are evidence for technical review, not a certification of quantum safety.</p>
      </div>
    </div>
  )
}
