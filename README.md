# Cybercrime Digital Evidence Analyzer

A defensive digital-forensics and incident-analysis platform for authorized investigators. Upload synthetic or legitimately obtained digital evidence, analyze it, reconstruct an incident timeline, identify suspicious activity, calculate risk, preserve evidence integrity, and generate investigation reports.

## Features

- **Authentication & RBAC** — Secure login with three roles: Admin, Investigator, Viewer
- **Case Management** — Create, search, filter, and track investigation cases
- **Evidence Upload** — Upload .txt, .log, .csv, .json files with automatic SHA-256 hashing
- **Evidence Integrity** — Cryptographic hashing to detect tampering
- **Log Parsing Engine** — Parse auth logs, web logs, CSV file/network events, and JSON
- **Detection Engine** — 7 rule-based detectors for suspicious patterns
- **Risk Scoring** — Transparent scoring with full explanation of how scores are calculated
- **Event Correlation** — Link related events across log sources
- **Timeline Reconstruction** — Visual chronological timeline with filtering
- **Indicator Management** — Extract and display IPs, usernames, filenames
- **Investigation Dashboard** — SOC-style overview with charts
- **Alert Details** — Expandable alerts with related events and detection reasoning
- **Report Generation** — Printable investigation reports
- **MITRE ATT&CK Mapping** — Potential technique mappings for detected behaviors
- **Audit Logging** — Complete chain of custody for all actions

## Technology Stack

| Component | Technology |
|---|---|
| Frontend | React, Vite, TypeScript, Tailwind CSS |
| Charts | Recharts |
| Icons | Lucide React |
| Routing | React Router |
| Backend | Supabase (PostgreSQL, Auth, Edge Functions, Storage) |
| Analysis Engine | Supabase Edge Function (Deno/TypeScript) |

## Architecture

```
React Frontend (Vite + TypeScript + Tailwind)
    │
    ├── Supabase Auth (login, sessions, RBAC)
    ├── Supabase Database (PostgreSQL with RLS)
    ├── Supabase Storage (evidence files)
    └── Supabase Edge Functions (analysis engine)
         ├── Log parsing (auth, web, CSV, JSON)
         ├── Detection rules (7 rule-based detectors)
         ├── Event correlation
         ├── Risk scoring
         └── Indicator extraction
```

## Database Schema

7 core tables with Row-Level Security:

- **profiles** — User data linked to auth.users (name, email, role)
- **cases** — Investigation cases (case_number, name, status, risk_level)
- **evidence** — Uploaded files (filename, sha256_hash, integrity_status)
- **events** — Normalized events (timestamp, event_type, severity, source_ip)
- **alerts** — Detection results (alert_type, severity, confidence, reason)
- **indicators** — IOCs (type, value, occurrence_count, risk_score)
- **audit_logs** — Action history (user_id, action, resource, timestamp)

## Detection Rules

| Rule | Description | Severity |
|---|---|---|
| 1 | Repeated failed logins from same IP (5+ in 5 min) | HIGH |
| 2 | Failed logins followed by success (account compromise) | CRITICAL |
| 3 | Sensitive file access (passwords, configs) | HIGH |
| 4 | Sensitive file modification | CRITICAL |
| 5 | Unusual login time (outside 8am-6pm) | MEDIUM |
| 6 | High volume from single source (20+ events) | MEDIUM |
| 7 | Suspicious sequence (failures → success → file access) | CRITICAL |

## Risk Scoring

Transparent project-specific scoring (max 100 points):

| Factor | Max Points |
|---|---|
| Alert severity | 40 |
| Event volume | 20 |
| Indicator count | 15 |
| Critical/high alert bonus | 25 |

| Score | Level |
|---|---|
| 0-24 | LOW |
| 25-49 | MEDIUM |
| 50-74 | HIGH |
| 75-100 | CRITICAL |

## Sample Evidence

Synthetic evidence files are in `sample_evidence/`:
- `auth.log` — Authentication logs (brute force scenario)
- `web.log` — Web server access logs
- `file_events.csv` — File access and modification events
- `network_events.csv` — Network connection events
- `events.json` — Pre-normalized JSON events

## Security Features

- Password hashing via Supabase Auth (bcrypt)
- JWT-based session management
- Row-Level Security on all database tables
- Role-Based Access Control (Admin, Investigator, Viewer)
- File upload validation (type, size, filename sanitization)
- SHA-256 cryptographic hashing for evidence integrity
- Path traversal prevention on uploaded filenames
- Immutable audit logs (no update/delete policies)
- Private storage bucket for evidence files

## Limitations

- Academic project — not for production use
- Rule-based detection only (no AI/ML anomaly detection yet)
- No real-time monitoring (analysis is triggered on demand)
- Evidence files limited to .txt, .log, .csv, .json
- No chain-of-c custody legal formatting
