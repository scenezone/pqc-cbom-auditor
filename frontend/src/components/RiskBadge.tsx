const styles: Record<string,string> = {
  'Quantum Vulnerable': 'bg-red-500/15 text-red-300 border-red-500/40',
  'Quantum Resistant Under Current Knowledge': 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40',
  'Unknown / Needs Review': 'bg-amber-500/15 text-amber-300 border-amber-500/40',
}
const short: Record<string,string> = {
  'Quantum Vulnerable': 'Quantum Vulnerable',
  'Quantum Resistant Under Current Knowledge': 'Quantum Resistant',
  'Unknown / Needs Review': 'Needs Review',
}
export default function RiskBadge({ classification }: { classification: string }) {
  return <span className={`rounded-full border px-2 py-1 text-xs font-medium ${styles[classification] ?? ''}`}>{short[classification] ?? classification}</span>
}
