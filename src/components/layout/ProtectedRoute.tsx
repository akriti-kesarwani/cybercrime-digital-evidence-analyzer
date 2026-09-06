import { Navigate } from 'react-router-dom'
import { useAuth } from '../../context/AuthContext'
import type { UserRole } from '../../types'

interface ProtectedRouteProps {
  children: React.ReactNode
  allowedRoles?: UserRole[]
}

export default function ProtectedRoute({ children, allowedRoles }: ProtectedRouteProps) {
  const { session, profile, loading } = useAuth()

  if (loading) {
    return (
      <div className="flex h-screen w-screen items-center justify-center bg-soc-bg">
        <div className="flex flex-col items-center gap-3">
          <div className="w-10 h-10 border-2 border-soc-border border-t-accent-cyan rounded-full animate-spin"></div>
          <p className="text-sm text-soc-muted">Loading...</p>
        </div>
      </div>
    )
  }

  if (!session) {
    return <Navigate to="/login" replace />
  }

  if (allowedRoles && profile && !allowedRoles.includes(profile.role)) {
    return (
      <div className="flex h-screen w-screen items-center justify-center bg-soc-bg">
        <div className="text-center">
          <p className="text-lg font-semibold text-severity-high">Access Denied</p>
          <p className="text-sm text-soc-muted mt-2">
            You do not have permission to view this page.
          </p>
        </div>
      </div>
    )
  }

  return <>{children}</>
}
