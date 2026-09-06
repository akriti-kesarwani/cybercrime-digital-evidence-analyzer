// MITRE ATT&CK technique mappings
// MITRE ATT&CK is a knowledge base of attacker tactics and techniques.
// Each technique has a standard ID (e.g., T1110 = Brute Force).
// We map our detection rules to potential MITRE techniques.
// We use "potential" language because we cannot be certain —
// the same pattern could have benign explanations.

import type { DetectionRule } from '../types'

export interface MitreMapping {
  technique: string
  name: string
  tactic: string
  confidence: number
  description: string
}

export const mitreMappings: Record<string, MitreMapping> = {
  RULE_1_BRUTE_FORCE: {
    technique: 'T1110',
    name: 'Brute Force',
    tactic: 'Credential Access',
    confidence: 80,
    description: 'Adversaries may use a brute-force technique to attempt access to accounts when passwords are unknown.',
  },
  RULE_2_ACCOUNT_COMPROMISE: {
    technique: 'T1078',
    name: 'Valid Accounts',
    tactic: 'Defense Evasion, Persistence, Privilege Escalation',
    confidence: 75,
    description: 'Adversaries may use credentials of existing accounts to gain initial access, persistence, or privilege escalation.',
  },
  RULE_3_SENSITIVE_ACCESS: {
    technique: 'T1083',
    name: 'File and Directory Discovery',
    tactic: 'Discovery',
    confidence: 65,
    description: 'Adversaries may enumerate files and directories to discover sensitive data.',
  },
  RULE_4_SENSITIVE_MODIFICATION: {
    technique: 'T1565',
    name: 'Stored Data Manipulation',
    tactic: 'Impact',
    confidence: 70,
    description: 'Adversaries may modify stored data to interfere with business operations.',
  },
  RULE_5_UNUSUAL_TIME: {
    technique: 'T1078',
    name: 'Valid Accounts',
    tactic: 'Defense Evasion',
    confidence: 50,
    description: 'Access at unusual times may indicate compromised credentials being used outside normal hours.',
  },
  RULE_6_HIGH_VOLUME: {
    technique: 'T1595',
    name: 'Active Scanning',
    tactic: 'Reconnaissance',
    confidence: 55,
    description: 'High volume of events from a single source may indicate automated activity.',
  },
  RULE_7_SUSPICIOUS_SEQUENCE: {
    technique: 'T1078',
    name: 'Valid Accounts',
    tactic: 'Initial Access',
    confidence: 85,
    description: 'A sequence of failed logins followed by success and sensitive access is consistent with account compromise.',
  },
}

export function getMitreMapping(ruleId: string): MitreMapping | null {
  return mitreMappings[ruleId] ?? null
}
