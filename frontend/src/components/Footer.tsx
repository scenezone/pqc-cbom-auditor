import { ShieldCheck } from 'lucide-react'

export default function Footer() {
  return (
    <footer className="border-t border-white/[0.06] bg-[#080d18]/70">
      <div className="mx-auto flex max-w-[1440px] flex-col gap-2 px-4 py-5 text-[11px] text-slate-500 sm:flex-row sm:items-center sm:justify-between sm:px-6 lg:px-8">
        <span className="inline-flex items-center gap-2"><ShieldCheck className="h-3.5 w-3.5 text-cyan-300/70" /> PQC Exposure &amp; CBOM Audit Platform</span>
        <span>Static analysis supports review; it does not guarantee complete cryptographic coverage.</span>
      </div>
    </footer>
  )
}
