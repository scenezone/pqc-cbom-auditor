import { useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { getFindings } from '../services/api'
import CryptoFindingsTable from '../components/CryptoFindingsTable'
import { ExportButtons } from '../components/ExportButtons'
import ErrorState from '../components/ErrorState'
import LoadingSkeleton from '../components/LoadingSkeleton'

export default function FindingsExplorer() {
  const { scanId } = useParams<{ scanId: string }>()
  const { data, isLoading, isError } = useQuery({
    queryKey: ['findings', scanId], queryFn: () => getFindings(scanId!), enabled: Boolean(scanId),
  })
  if (isLoading) return <LoadingSkeleton />
  if (isError || !data) return <ErrorState message="Unable to load findings." />
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">Findings Explorer</h1>
        <ExportButtons scanId={scanId!} />
      </div>
      <CryptoFindingsTable findings={data} />
    </div>
  )
}
