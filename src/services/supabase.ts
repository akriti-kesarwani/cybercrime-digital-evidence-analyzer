import { createClient } from '@supabase/supabase-js'

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL as string
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY as string

if (!supabaseUrl || !supabaseAnonKey) {
  throw new Error(
    'Missing Supabase environment variables. Check .env for VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY.'
  )
}

export const supabase = createClient(supabaseUrl, supabaseAnonKey, {
  auth: {
    persistSession: true,
    autoRefreshToken: true,
    detectSessionInUrl: true,
  },
})

// Table name constants for type safety
export const TABLES = {
  PROFILES: 'profiles',
  CASES: 'cases',
  EVIDENCE: 'evidence',
  EVENTS: 'events',
  ALERTS: 'alerts',
  INDICATORS: 'indicators',
  AUDIT_LOGS: 'audit_logs',
} as const
