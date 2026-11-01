import { Link, useLocation } from 'react-router-dom'
import { ArrowUpRight, Atom, ShieldCheck } from 'lucide-react'

const links = [
  { to: '/', label: 'Overview' },
  { to: '/projects', label: 'Audits' },
  { to: '/methodology', label: 'Methodology' },
]

export default function Navbar() {
  const { pathname } = useLocation()
  return (
    <header className="sticky top-0 z-30 border-b border-white/[0.07] bg-[#080d18]/90 backdrop-blur-xl">
      <div className="mx-auto flex h-[68px] max-w-[1440px] items-center justify-between gap-4 px-4 sm:px-6 lg:px-8">
        <Link to="/" className="group flex min-w-0 items-center gap-3" aria-label="PQC Auditor home">
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-cyan-300/20 bg-cyan-300/[0.09] text-cyan-200 shadow-[0_0_24px_rgba(34,211,238,.08)]">
            <ShieldCheck className="h-[19px] w-[19px]" strokeWidth={1.8} />
          </span>
          <span className="min-w-0">
            <span className="block truncate text-[13px] font-semibold tracking-wide text-slate-100">PQC Auditor</span>
            <span className="hidden text-[10px] tracking-[.12em] text-slate-500 sm:block">CRYPTOGRAPHIC INVENTORY</span>
          </span>
        </Link>

        <nav aria-label="Main navigation" className="flex items-center gap-1 rounded-xl border border-white/[0.06] bg-white/[0.025] p-1">
          {links.map(link => {
            const active = link.to === '/' ? pathname === '/' : pathname.startsWith(link.to)
            return (
              <Link key={link.to} to={link.to} aria-label={link.label} title={link.label} aria-current={active ? 'page' : undefined}
                className={`rounded-lg px-2.5 py-2 text-[11px] font-medium transition sm:px-4 sm:text-[13px] ${active ? 'bg-white/[0.09] text-white shadow-sm' : 'text-slate-400 hover:text-slate-100'}`}>
                {link.to === '/methodology' ? <><Atom className="h-4 w-4 sm:hidden" /><span className="hidden sm:inline">{link.label}</span></> : link.label}
              </Link>
            )
          })}
        </nav>

        <Link to="/new-audit" aria-label="Start a new assessment" className="btn-primary !rounded-lg !px-2.5 !py-2 text-xs sm:!px-4 sm:text-sm">
          <span className="hidden sm:inline">New assessment</span>
          <ArrowUpRight className="h-3.5 w-3.5" />
        </Link>
      </div>
    </header>
  )
}
