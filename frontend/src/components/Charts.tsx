import { Bar, BarChart, CartesianGrid, Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

const COLORS: Record<string,string> = {
  'Quantum Vulnerable': '#EF4444',
  'Quantum Resistant Under Current Knowledge': '#10B981',
  'Unknown / Needs Review': '#F59E0B',
}

export function RiskDistributionChart({ data }: { data: Record<string,number> }) {
  const d = Object.entries(data).map(([name,value]) => ({name,value}))
  return (
    <div className="card">
      <h3 className="mb-4 font-semibold">Classification Distribution</h3>
      <ResponsiveContainer width="100%" height={260}>
        <PieChart><Pie data={d} dataKey="value" nameKey="name" outerRadius={90} label>
          {d.map(e => <Cell key={e.name} fill={COLORS[e.name] ?? '#6366F1'} />)}
        </Pie><Tooltip /><Legend /></PieChart>
      </ResponsiveContainer>
    </div>
  )
}

export function AlgorithmDistributionChart({ data }: { data: Record<string,number> }) {
  const d = Object.entries(data).sort((a,b)=>b[1]-a[1]).slice(0,10).map(([name,value])=>({name,value}))
  return (
    <div className="card">
      <h3 className="mb-4 font-semibold">Algorithm Distribution</h3>
      <ResponsiveContainer width="100%" height={260}>
        <BarChart data={d}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1B2A4A" />
          <XAxis dataKey="name" stroke="#94A3B8" fontSize={11} />
          <YAxis stroke="#94A3B8" allowDecimals={false} />
          <Tooltip /><Bar dataKey="value" fill="#22D3EE" radius={[4,4,0,0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}

export function SeverityChart({ data }: { data: Record<string,number> }) {
  const order = ['Critical','High','Medium','Low']
  const colors = ['#EF4444','#F97316','#F59E0B','#22C55E']
  const d = order.map(n => ({name:n, value:data[n] ?? 0}))
  return (
    <div className="card">
      <h3 className="mb-4 font-semibold">Severity Distribution</h3>
      <ResponsiveContainer width="100%" height={260}>
        <BarChart data={d}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1B2A4A" />
          <XAxis dataKey="name" stroke="#94A3B8" />
          <YAxis stroke="#94A3B8" allowDecimals={false} />
          <Tooltip /><Bar dataKey="value" radius={[4,4,0,0]}>
            {d.map((e,i) => <Cell key={e.name} fill={colors[i]} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
