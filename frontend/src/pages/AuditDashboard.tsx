import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { getScanSummary } from '../services/api'
import AuditSummaryCards from '../components/AuditSummaryCards'
import { AlgorithmDistributionChart, RiskDistributionChart, SeverityChart } from '../components/Charts'
import MigrationPriorityList from '../components/MigrationPriorityList'
import FeedbackForm from '../components/FeedbackForm'
import LoadingSkeleton from '../components/LoadingSkeleton'
import ErrorState from '../components/ErrorState'
import TlsAssessmentPanel from '../components/TlsAssessmentPanel'

export default function AuditDashboard() {
  const { scanId } = useParams<{ scanId: string }>()
  const { data, isLoading, isError } = useQuery({
    queryKey: ['scan-summary', scanId],
    queryFn: () => getScanSummary(scanId!), enabled: Boolean(scanId),
  })
  if (isLoading) return <LoadingSkeleton />
  if (isError || !data) return <ErrorState message="Unable to load audit dashboard." />
  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 border-b border-white/[0.07] pb-5 sm:flex-row sm:items-end sm:justify-between">
        <div className="min-w-0"><p className="eyebrow">{data.scan.repository_source_type === 'https_endpoint' ? 'HTTPS endpoint assessment' : 'Audit dashboard'}</p><h1 className="mt-2 truncate text-2xl font-semibold tracking-tight text-white">{data.scan.repository_name}</h1>
          <p className="mt-1 break-all text-xs text-slate-500">{data.scan.repository_source_type === 'https_endpoint' ? data.scan.tls_assessment?.target : 'Review exposure, findings, and migration priorities.'}</p></div>
        <div className="flex flex-wrap gap-2">
          <Link className="btn-secondary !py-2 text-xs" to={`/scans/${scanId}/findings`}>Findings</Link>
          <Link className="btn-secondary !py-2 text-xs" to={`/scans/${scanId}/cbom`}>CBOM</Link>
          <Link className="btn-secondary !py-2 text-xs" to={`/scans/${scanId}/reports`}>Reports</Link>
        </div>
      </div>
      <AuditSummaryCards summary={data} />
      {data.scan.tls_assessment && <TlsAssessmentPanel assessment={data.scan.tls_assessment} />}
      <div className="grid gap-4 lg:grid-cols-3">
        <RiskDistributionChart data={data.classification_distribution} />
        <SeverityChart data={data.severity_distribution} />
        <AlgorithmDistributionChart data={data.algorithm_distribution} />
      </div>
      <MigrationPriorityList findings={data.top_findings} />
      <FeedbackForm scanId={scanId} />
    </div>
  )
}
