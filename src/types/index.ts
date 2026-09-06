// ============================================================
// Core Database Types — mirrors the Supabase schema
// ============================================================

export type UserRole = 'ADMIN' | 'INVESTIGATOR' | 'VIEWER'

export type CaseStatus = 'OPEN' | 'UNDER_INVESTIGATION' | 'CLOSED' | 'ARCHIVED'
export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
export type IntegrityStatus = 'VERIFIED' | 'COMPROMISED' | 'PENDING'
export type IndicatorType = 'IP' | 'USERNAME' | 'FILENAME' | 'DOMAIN' | 'URL' | 'HASH'

export type EventType =
  | 'LOGIN_FAILED'
  | 'LOGIN_SUCCESS'
  | 'LOGOUT'
  | 'FILE_ACCESS'
  | 'FILE_MODIFY'
  | 'FILE_DELETE'
  | 'NETWORK_CONNECTION'
  | 'NETWORK_DNS'
  | 'NETWORK_BLOCKED'
  | 'PRIVILEGE_ESCALATION'
  | 'OTHER'

export interface Profile {
  id: string
  name: string
  email: string
  role: UserRole
  created_at: string
}

export interface Case {
  id: string
  case_number: string
  name: string
  description: string | null
  status: CaseStatus
  risk_level: RiskLevel | null
  created_by: string
  created_at: string
  updated_at: string
  // Joined fields
  created_by_profile?: Pick<Profile, 'name' | 'email'>
  evidence_count?: number
  event_count?: number
  alert_count?: number
}

export interface Evidence {
  id: string
  case_id: string
  filename: string
  original_filename: string
  file_type: string
  file_size: number
  sha256_hash: string
  storage_path: string
  uploaded_by: string
  uploaded_at: string
  integrity_status: IntegrityStatus
  parsed: boolean
  analysis_status?: 'PENDING' | 'PROCESSING' | 'COMPLETED' | 'FAILED'
  analysis_error?: string | null
  analysis_started_at?: string | null
  analysis_completed_at?: string | null
  verified_sha256_hash?: string | null
  // Joined fields
  uploaded_by_profile?: Pick<Profile, 'name' | 'email'>
}

export interface EventRecord {
  id: string
  case_id: string
  evidence_id: string | null
  timestamp: string
  event_type: EventType
  username: string | null
  source_ip: string | null
  destination_ip: string | null
  source: string | null
  description: string | null
  severity: Severity
  raw_data: Record<string, unknown> | null
}

export interface Alert {
  id: string
  case_id: string
  alert_type: string
  severity: Severity
  confidence: number
  reason: string
  related_event_ids: string[] | null
  detection_rule: string
  created_at: string
  // Joined fields
  primary_event?: EventRecord
}

export interface Indicator {
  id: string
  case_id: string
  type: IndicatorType
  value: string
  description: string | null
  occurrence_count: number
  risk_score: number | null
}

export interface AuditLog {
  id: string
  user_id: string | null
  action: string
  resource: string | null
  resource_id: string | null
  metadata: Record<string, unknown> | null
  timestamp: string
  // Joined fields
  user_profile?: Pick<Profile, 'name' | 'email'> | null
}

// ============================================================
// Detection Engine Types
// ============================================================

export interface DetectionRule {
  id: string
  name: string
  description: string
  severity: Severity
  mitreTechnique?: string
  mitreName?: string
}

export interface DetectionResult {
  rule_id: string
  rule_name: string
  severity: Severity
  confidence: number
  reason: string
  related_event_ids: string[]
  detection_rule: string
  mitre_technique?: string
  mitre_name?: string
}

// ============================================================
// Risk Scoring Types
// ============================================================

export interface RiskFactor {
  factor: string
  weight: number
  value: number
  contribution: number
}

export interface RiskScore {
  level: RiskLevel
  total_score: number
  max_score: number
  factors: RiskFactor[]
  explanation: string
}

// ============================================================
// Report Types
// ============================================================

export interface InvestigationReport {
  case: Case
  evidence: Evidence[]
  events: EventRecord[]
  alerts: Alert[]
  indicators: Indicator[]
  risk_score: RiskScore | null
  generated_at: string
  generated_by: string
}
