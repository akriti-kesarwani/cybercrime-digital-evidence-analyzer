import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import type { Session, User } from '@supabase/supabase-js'
import { supabase } from '../services/supabase'
import { logAuditAction } from '../services/audit'
import type { Profile, UserRole } from '../types'

interface AuthContextValue {
  session: Session | null
  user: User | null
  profile: Profile | null
  loading: boolean
  signIn: (email: string, password: string) => Promise<{ error: string | null }>
  signUp: (email: string, password: string, name: string) => Promise<{ error: string | null }>
  signOut: () => Promise<void>
  hasRole: (...roles: UserRole[]) => boolean
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(null)
  const [user, setUser] = useState<User | null>(null)
  const [profile, setProfile] = useState<Profile | null>(null)
  const [loading, setLoading] = useState(true)

  async function fetchProfile(userId: string) {
    const { data, error } = await supabase
      .from('profiles')
      .select('id, name, email, role, created_at')
      .eq('id', userId)
      .maybeSingle()

    if (error) {
      console.error('Error fetching profile:', error.message)
      return null
    }
    return data as Profile | null
  }

  useEffect(() => {
    let mounted = true

    async function loadSession() {
      const { data, error } = await supabase.auth.getSession()
      if (!mounted) return
      if (error) {
        console.error('Error loading authentication session:', error.message)
        setLoading(false)
        return
      }

      setSession(data.session)
      setUser(data.session?.user ?? null)
      if (data.session?.user) {
        setProfile(await fetchProfile(data.session.user.id))
      }
      setLoading(false)
    }

    loadSession()

    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((_event, session) => {
      if (!mounted) return
      setSession(session)
      setUser(session?.user ?? null)
      setLoading(true)

      if (session?.user) {
        // Defer the profile query so it does not run inside Supabase's
        // auth-state callback lock.
        setTimeout(() => {
          fetchProfile(session.user.id).then((p) => {
            if (mounted) {
              setProfile(p)
              setLoading(false)
            }
          })
        }, 0)
      } else {
        setProfile(null)
        setLoading(false)
      }
    })

    return () => {
      mounted = false
      subscription.unsubscribe()
    }
  }, [])

  async function signIn(email: string, password: string) {
    const { data, error } = await supabase.auth.signInWithPassword({
      email: email.trim(),
      password,
    })
    if (!error && data.user) {
      await logAuditAction(data.user.id, 'LOGIN', 'auth', data.user.id)
    }
    return { error: error?.message ?? null }
  }

  async function signUp(email: string, password: string, name: string) {
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: { data: { name } },
    })
    if (error) return { error: error.message }
    if (data.user) {
      // Profile is created via database trigger on auth.users insert
      // Wait briefly for the trigger to complete
      await new Promise((r) => setTimeout(r, 500))
    }
    return { error: null }
  }

  async function signOut() {
    const currentUserId = user?.id
    if (currentUserId) {
      await logAuditAction(currentUserId, 'LOGOUT', 'auth', currentUserId)
    }
    await supabase.auth.signOut()
    setProfile(null)
  }

  function hasRole(...roles: UserRole[]) {
    if (!profile) return false
    return roles.includes(profile.role)
  }

  return (
    <AuthContext.Provider
      value={{ session, user, profile, loading, signIn, signUp, signOut, hasRole }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
