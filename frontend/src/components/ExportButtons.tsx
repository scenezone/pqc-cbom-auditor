import { Download } from 'lucide-react'
import { downloadFile, generateCbom, generateReport } from '../services/api'

export function ExportButtons({ scanId }: { scanId: string }) {
  return (
    <div className="flex flex-wrap gap-2">
      <button className="btn-secondary" onClick={() => downloadFile(`/api/scans/${scanId}/findings/export?format=csv`)}>
        <Download className="h-4 w-4" /> CSV</button>
      <button className="btn-secondary" onClick={() => downloadFile(`/api/scans/${scanId}/findings/export?format=json`)}>
        <Download className="h-4 w-4" /> JSON</button>
      <button className="btn-secondary" onClick={async () => { await generateCbom(scanId); downloadFile(`/api/scans/${scanId}/cbom/download`) }}>
        <Download className="h-4 w-4" /> CBOM</button>
      <button className="btn-primary" onClick={async () => { await generateReport(scanId); downloadFile(`/api/scans/${scanId}/reports/download`) }}>
        <Download className="h-4 w-4" /> Executive PDF</button>
    </div>
  )
}
