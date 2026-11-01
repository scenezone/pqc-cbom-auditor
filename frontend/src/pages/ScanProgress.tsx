import { useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { getScanSummary } from '../services/api'
import ScanProgressComponent from '../components/ScanProgress'

export default function ScanProgress() {
  const { scanId } = useParams<{ scanId: string }>()
  const { data, isLoading } = useQuery({
    queryKey: ['scan-status', scanId],
    queryFn: () => getScanSummary(scanId!),
    refetchInterval: 3000, enabled: Boolean(scanId),
  })
  if (isLoading || !data) return <p className="text-slate-400">Loading scan status…</p>
  return <ScanProgressComponent scanId={scanId!} summary={data} />
}
