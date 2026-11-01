export type QuantumClassification =
  | 'Quantum Vulnerable'
  | 'Quantum Resistant Under Current Knowledge'
  | 'Unknown / Needs Review'

export interface Finding {
  finding_id: string; scan_id: string; language: string; file_path: string
  start_line: number; end_line: number; symbol_name: string; library_name: string
  imported_symbol: string; crypto_operation: string; algorithm: string
  algorithm_variant: string; key_size?: number | null; cryptographic_purpose: string
  evidence_type: string; evidence_snippet: string; detection_rule_id: string
  detection_confidence: 'High' | 'Medium' | 'Low'
  quantum_classification: QuantumClassification
  classification_reason: string; classification_reference: string
  severity_score: number; severity_category: 'Critical' | 'High' | 'Medium' | 'Low'
  migration_recommendation: string; algorithm_family: string
}

export interface ScanItem {
  scan_id: string
  repository_name: string
  repository_source_type: string
  scan_status: string
  languages?: string[]
  total_files?: number
  scanned_files?: number
  skipped_files?: number
  total_findings?: number
  started_at?: string
  completed_at?: string | null
  error_summary?: string | null
  tls_assessment?: TlsAssessment
  business_context?: {
    business_criticality?: string
    data_sensitivity?: string
    data_retention_horizon?: string
    external_exposure?: string
  }
}

export interface TlsCertificate {
  public_key_algorithm?: string
  public_key_bits?: number | null
  public_key_quantum_status?: string
  signature_algorithm?: string
  signature_quantum_status?: string
  validation_status?: string
  parse_error?: string
}

export interface TlsAssessment {
  target: string
  status: string
  error?: string
  protocols: { version: string; status: string; pqc_status: string; negotiated_group?: string | null; cipher_suite?: { name: string; iana_id?: string; algorithms: string[] } | null; reason?: string | null }[]
  groups: { name: string; iana_id: string; protocol: string; type: string; pqc_algorithm?: string | null; status: string; negotiated_group?: string | null; reason?: string | null }[]
  certificate?: TlsCertificate | null
  certificates?: TlsCertificate[]
  findings: { title: string; severity: string; quantum_status: string; detail: string }[]
}

export interface ScanConfig {
  scan_name: string
  business_criticality: string
  data_sensitivity: string
  data_retention_horizon: string
  external_exposure: string
  tls_target_url?: string
}

export interface ScanSummary {
  scan: ScanItem
  counts: { files_scanned: number; files_skipped: number; findings: number; unique_assets: number
            quantum_vulnerable: number; quantum_resistant: number; needs_review: number; high_priority: number }
  classification_distribution: Record<string, number>
  severity_distribution: Record<string, number>
  algorithm_distribution: Record<string, number>
  language_distribution: Record<string, number>
  top_findings: Finding[]
}
