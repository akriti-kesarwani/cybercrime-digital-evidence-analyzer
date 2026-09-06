import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { ShieldCheck, Mail, Lock, AlertCircle, User, Eye, EyeOff } from 'lucide-react'
import { useAuth } from '../context/AuthContext'

export default function Login() {
  const navigate = useNavigate()
  const { session, signIn, signUp } = useAuth()
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [name, setName] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (session) navigate('/dashboard', { replace: true })
  }, [session, navigate])

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setLoading(true)

    if (mode === 'register') {
      if (name.trim().length < 2) {
        setError('Name must be at least 2 characters.')
        setLoading(false)
        return
      }
      if (password.length < 8) {
        setError('Password must be at least 8 characters.')
        setLoading(false)
        return
      }
      const { error } = await signUp(email, password, name)
      if (error) {
        setError(error)
        setLoading(false)
        return
      }
      // After signup, sign in automatically
      const { error: signInError } = await signIn(email, password)
      if (signInError) {
        setError(signInError)
        setLoading(false)
        return
      }
      setError('Account created. Check your email to confirm the account before signing in.')
      setMode('login')
      setLoading(false)
      return
    } else {
      const { error } = await signIn(email, password)
      if (error) {
        setError(error)
        setLoading(false)
        return
      }
    }
  }

  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-soc-bg px-4">
      {/* Background grid pattern */}
      <div
        className="absolute inset-0 opacity-[0.03]"
        style={{
          backgroundImage:
            'linear-gradient(#06b6d4 1px, transparent 1px), linear-gradient(90deg, #06b6d4 1px, transparent 1px)',
          backgroundSize: '40px 40px',
        }}
      />

      <div className="relative w-full max-w-md">
        {/* Logo */}
        <div className="flex flex-col items-center mb-8">
          <div className="w-16 h-16 rounded-2xl bg-accent-blue/10 flex items-center justify-center mb-4 border border-accent-blue/20">
            <ShieldCheck className="w-9 h-9 text-accent-cyan" />
          </div>
          <h1 className="text-xl font-bold text-soc-text">
            Cybercrime Digital Evidence Analyzer
          </h1>
          <p className="text-sm text-soc-muted mt-1">
            Secure digital forensics investigation platform
          </p>
        </div>

        {/* Form card */}
        <div className="card p-8 animate-fade-in">
          <div className="flex gap-1 mb-6 bg-soc-bg rounded-md p-1">
            <button
              onClick={() => setMode('login')}
              className={`flex-1 py-2 text-sm font-medium rounded transition-colors ${
                mode === 'login'
                  ? 'bg-soc-hover text-soc-text'
                  : 'text-soc-muted hover:text-soc-text'
              }`}
            >
              Sign In
            </button>
            <button
              onClick={() => setMode('register')}
              className={`flex-1 py-2 text-sm font-medium rounded transition-colors ${
                mode === 'register'
                  ? 'bg-soc-hover text-soc-text'
                  : 'text-soc-muted hover:text-soc-text'
              }`}
            >
              Register
            </button>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            {mode === 'register' && (
              <div>
                <label className="block text-xs font-medium text-soc-muted mb-1.5">
                  Full Name
                </label>
                <div className="relative">
                  <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-soc-muted" />
                  <input
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="Jane Investigator"
                    className="input-field pl-9"
                    required
                  />
                </div>
              </div>
            )}

            <div>
              <label className="block text-xs font-medium text-soc-muted mb-1.5">
                Email
              </label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-soc-muted" />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="investigator@example.com"
                  className="input-field pl-9"
                  required
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-soc-muted mb-1.5">
                Password
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-soc-muted" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={mode === 'register' ? 'At least 8 characters' : '••••••••'}
                  className="input-field pl-9 pr-9"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-soc-muted hover:text-soc-text transition-colors"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {error && (
              <div className="flex items-start gap-2 p-3 bg-severity-critical/10 border border-severity-critical/30 rounded-md animate-fade-in">
                <AlertCircle className="w-4 h-4 text-severity-critical flex-shrink-0 mt-0.5" />
                <p className="text-sm text-severity-critical">{error}</p>
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading
                ? 'Please wait...'
                : mode === 'login'
                  ? 'Sign In'
                  : 'Create Account'}
            </button>
          </form>

          <p className="text-xs text-soc-muted text-center mt-6">
            Access is restricted to authorized personnel only.
            <br />
            All actions are recorded in the audit log.
          </p>
        </div>
      </div>
    </div>
  )
}
