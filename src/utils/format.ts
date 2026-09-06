import type { Severity, RiskLevel } from '../types'

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

export function formatTimestamp(ts: string): string {
  return new Date(ts).toLocaleString()
}

export function formatShortHash(hash: string, length = 16): string {
  if (hash.length <= length * 2) return hash
  return `${hash.substring(0, length)}...`
}

export const severityOrder: Record<Severity, number> = {
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
}

export function severityToColor(sev: Severity): string {
  const colors: Record<Severity, string> = {
    LOW: '#3b82f6',
    MEDIUM: '#f59e0b',
    HIGH: '#f97316',
    CRITICAL: '#ef4444',
  }
  return colors[sev]
}

export function riskLevelToColor(level: RiskLevel): string {
  const colors: Record<RiskLevel, string> = {
    LOW: '#3b82f6',
    MEDIUM: '#f59e0b',
    HIGH: '#f97316',
    CRITICAL: '#ef4444',
  }
  return colors[level]
}

export const eventTypeLabels: Record<string, string> = {
  LOGIN_FAILED: 'Failed Login',
  LOGIN_SUCCESS: 'Successful Login',
  LOGOUT: 'Logout',
  FILE_ACCESS: 'File Access',
  FILE_MODIFY: 'File Modified',
  FILE_DELETE: 'File Deleted',
  NETWORK_CONNECTION: 'Network Connection',
  NETWORK_DNS: 'DNS Query',
  NETWORK_BLOCKED: 'Network Blocked',
  PRIVILEGE_ESCALATION: 'Privilege Escalation',
  OTHER: 'Other',
}
