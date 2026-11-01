import axios from 'axios'
import type { Finding, ScanConfig, ScanItem, ScanSummary } from '../types'

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api',
  timeout: 30000,
})

export async function listScans(): Promise<ScanItem[]> {
  const r = await api.get('/scans')
  return r.data
}

export async function deleteScan(scanId: string) {
  const r = await api.delete(`/scans/${scanId}`)
  return r.data
}

export async function scanRepositorySource(
  sourceType: 'zip' | 'github',
  file: File | null,
  repositoryUrl: string,
  config: ScanConfig,
) {
  const form = new FormData()
  form.append('source_type', sourceType)
  form.append('scan_name', config.scan_name)
  form.append('business_criticality', config.business_criticality)
  form.append('data_sensitivity', config.data_sensitivity)
  form.append('data_retention_horizon', config.data_retention_horizon)
  form.append('external_exposure', config.external_exposure)
  form.append('tls_target_url', config.tls_target_url || '')
  if (sourceType === 'zip' && file) form.append('file', file)
  if (sourceType === 'github') form.append('repository_url', repositoryUrl)
  const r = await api.post('/scans/source', form)
  return r.data
}

export async function scanHttpsEndpoint(payload: object) {
  const r = await api.post('/scans/https', payload)
  return r.data
}

export async function getScanSummary(scanId: string): Promise<ScanSummary> {
  const r = await api.get(`/scans/${scanId}/summary`)
  return r.data
}

export async function getFindings(scanId: string): Promise<Finding[]> {
  const r = await api.get(`/scans/${scanId}/findings`)
  return r.data
}

export async function generateCbom(scanId: string) {
  const r = await api.post(`/scans/${scanId}/cbom/generate`)
  return r.data
}

export async function generateReport(scanId: string) {
  const r = await api.post(`/scans/${scanId}/reports/generate`)
  return r.data
}

export function downloadFile(url: string) {
  window.open(url, '_blank', 'noopener,noreferrer')
}
