import type { ScanConfig } from '../types'

interface Props {
  config: ScanConfig
  onChange: (c: ScanConfig) => void
}

export default function ScanConfiguration({ config, onChange }: Props) {
  return (
    <div className="card">
      <div className="mb-5 border-b border-white/[0.07] pb-4">
        <h2 className="text-sm font-semibold text-slate-100">Business context</h2>
        <p className="mt-1 text-xs leading-5 text-slate-500">
          These assumptions help prioritize migration risk for the organization.
        </p>
      </div>
      <div className="mt-4 grid gap-4 md:grid-cols-2">
        <label className="text-xs font-medium text-slate-300 md:col-span-2">
          <span className="mb-1.5 block">Assessment name</span>
          <input
            type="text"
            value={config.scan_name}
            onChange={e => onChange({ ...config, scan_name: e.target.value })}
            placeholder="e.g. Core Payment Service Audit"
            className="field-control"
          />
        </label>

        <label className="text-xs font-medium text-slate-300">
          <span className="mb-1.5 block">Business criticality</span>
          <select
            value={config.business_criticality}
            onChange={e => onChange({ ...config, business_criticality: e.target.value })}
            className="field-control"
          >
            <option value="Critical">Critical (Mission essential / Core)</option>
            <option value="Very High">Very High (High commercial impact)</option>
            <option value="High">High (Significant operational impact)</option>
            <option value="Moderate">Moderate (Standard business tier)</option>
            <option value="Low">Low (Internal non-critical)</option>
          </select>
        </label>

        <label className="text-xs font-medium text-slate-300">
          <span className="mb-1.5 block">Data sensitivity</span>
          <select
            value={config.data_sensitivity}
            onChange={e => onChange({ ...config, data_sensitivity: e.target.value })}
            className="field-control"
          >
            <option value="Restricted">Restricted (Secrets, Keys, PII)</option>
            <option value="Confidential">Confidential (Proprietary data)</option>
            <option value="Internal">Internal (Internal operational)</option>
            <option value="Public">Public (Non-sensitive)</option>
          </select>
        </label>

        <label className="text-xs font-medium text-slate-300">
          <span className="mb-1.5 block">Data retention horizon</span>
          <select
            value={config.data_retention_horizon}
            onChange={e => onChange({ ...config, data_retention_horizon: e.target.value })}
            className="field-control"
          >
            <option value="More than 15 years">More than 15 years (Extreme quantum risk window)</option>
            <option value="7-15 years">7-15 years (Long-lived secret window)</option>
            <option value="3-7 years">3-7 years (Standard retention)</option>
            <option value="1-3 years">1-3 years (Medium-term data)</option>
            <option value="Less than 1 year">Less than 1 year (Short-lived ephemeral)</option>
          </select>
        </label>

        <label className="text-xs font-medium text-slate-300">
          <span className="mb-1.5 block">External exposure</span>
          <select
            value={config.external_exposure}
            onChange={e => onChange({ ...config, external_exposure: e.target.value })}
            className="field-control"
          >
            <option value="Public">Public (Internet-facing service)</option>
            <option value="Partner">Partner (Ecosystem / Partner network)</option>
            <option value="Internal">Internal (Private isolated network)</option>
          </select>
        </label>
      </div>
    </div>
  )
}
