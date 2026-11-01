import { useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { generateCbom } from '../services/api'
import CBOMViewer from '../components/CBOMViewer'
import { ExportButtons } from '../components/ExportButtons'
import LoadingSkeleton from '../components/LoadingSkeleton'
import ErrorState from '../components/ErrorState'

export default function CBOMViewerPage() {
  const { scanId } = useParams<{ scanId: string }>()
  const { data, isLoading, isError } = useQuery({
    queryKey: ['cbom', scanId], queryFn: () => generateCbom(scanId!), enabled: Boolean(scanId),
  })
  if (isLoading) return <LoadingSkeleton />
  if (isError || !data) return <ErrorState message="Unable to generate CBOM." />
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">CycloneDX CBOM</h1>
        <ExportButtons scanId={scanId!} />
      </div>
      <CBOMViewer validation={data.validation} componentCount={data.component_count} cbom={data.cbom} />
    </div>
  )
}
