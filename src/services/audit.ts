import { supabase } from './supabase'

// Records an action in the audit log.
// In digital forensics, an audit trail proves WHO did WHAT and WHEN —
// this is part of maintaining "chain of custody" for the investigation.
export async function logAuditAction(
  userId: string | null,
  action: string,
  resource: string | null = null,
  resourceId: string | null = null,
  metadata: Record<string, unknown> = {}
) {
  const { error } = await supabase.from('audit_logs').insert({
    user_id: userId,
    action,
    resource,
    resource_id: resourceId,
    metadata,
  })

  if (error) {
    console.error('Failed to write audit log:', error.message)
  }
}
