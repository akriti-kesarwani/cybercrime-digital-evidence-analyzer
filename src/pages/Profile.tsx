import { useAuth } from '../context/AuthContext'
import { User, Mail, Shield, Calendar } from 'lucide-react'

export default function Profile() {
  const { profile, user } = useAuth()

  if (!profile) {
    return (
      <div className="flex items-center justify-center h-96">
        <p className="text-soc-muted">Loading profile...</p>
      </div>
    )
  }

  return (
    <div className="space-y-6 animate-fade-in max-w-2xl">
      <div>
        <h1 className="text-2xl font-bold text-soc-text">Profile</h1>
        <p className="text-sm text-soc-muted mt-1">Your account information</p>
      </div>

      <div className="card p-6">
        <div className="flex items-center gap-4 mb-6">
          <div className="w-16 h-16 rounded-full bg-accent-blue/20 flex items-center justify-center text-accent-blue font-bold text-2xl">
            {profile.name.charAt(0).toUpperCase()}
          </div>
          <div>
            <h2 className="text-lg font-semibold text-soc-text">{profile.name}</h2>
            <span className={`badge-${profile.role === 'ADMIN' ? 'critical' : profile.role === 'INVESTIGATOR' ? 'medium' : 'low'}`}>
              {profile.role}
            </span>
          </div>
        </div>

        <div className="space-y-4">
          <div className="flex items-center gap-3 p-3 rounded-md bg-soc-bg">
            <User className="w-4 h-4 text-soc-muted" />
            <div>
              <p className="text-xs text-soc-muted">Name</p>
              <p className="text-sm text-soc-text">{profile.name}</p>
            </div>
          </div>
          <div className="flex items-center gap-3 p-3 rounded-md bg-soc-bg">
            <Mail className="w-4 h-4 text-soc-muted" />
            <div>
              <p className="text-xs text-soc-muted">Email</p>
              <p className="text-sm text-soc-text">{profile.email}</p>
            </div>
          </div>
          <div className="flex items-center gap-3 p-3 rounded-md bg-soc-bg">
            <Shield className="w-4 h-4 text-soc-muted" />
            <div>
              <p className="text-xs text-soc-muted">Role</p>
              <p className="text-sm text-soc-text">{profile.role}</p>
            </div>
          </div>
          <div className="flex items-center gap-3 p-3 rounded-md bg-soc-bg">
            <Calendar className="w-4 h-4 text-soc-muted" />
            <div>
              <p className="text-xs text-soc-muted">Member Since</p>
              <p className="text-sm text-soc-text">{new Date(profile.created_at).toLocaleDateString()}</p>
            </div>
          </div>
          {user && (
            <div className="flex items-center gap-3 p-3 rounded-md bg-soc-bg">
              <Shield className="w-4 h-4 text-soc-muted" />
              <div>
                <p className="text-xs text-soc-muted">User ID</p>
                <p className="text-sm font-mono text-soc-text">{user.id}</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
